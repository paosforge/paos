#!/usr/bin/python3
"""One tools session, launched only by the guest PID1. Creator: Codex / rc-vm.
The C CONNECT service alone interprets the native hostname stream. This
broker selects one pinned CLI, relays its PTY, and never respawns either child.
"""
import ctypes as C
import errno
import fcntl
import os
import resource
import select
import stat
import subprocess
import sys
import termios
import time
import tty

libc = C.CDLL(None, use_errno=True)
TOOL_UID = 1000
BASE_ENV = {'PATH': '/usr/bin', 'LANG': 'C', 'LC_ALL': 'C'}


class CapHeader(C.Structure):
    _fields_ = [('version', C.c_uint32), ('pid', C.c_int)]


class CapData(C.Structure):
    _fields_ = [('effective', C.c_uint32), ('permitted', C.c_uint32),
                ('inheritable', C.c_uint32)]


def libcall(name, *args):
    if getattr(libc, name)(*args) != 0:
        raise OSError(C.get_errno(), name)


def harden():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libcall('prctl', 38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    libcall('prctl', 4, 0, 0, 0, 0)   # PR_SET_DUMPABLE; exec/setuid reset it


def zero_caps():
    libcall('prctl', 47, 4, 0, 0, 0)  # PR_CAP_AMBIENT_CLEAR_ALL
    header = CapHeader(0x20080522, 0)
    data = (CapData * 2)()
    libcall('capset', C.byref(header), C.byref(data))
    libcall('capget', C.byref(header), C.byref(data))
    if any(value for row in data for value in
           (row.effective, row.permitted, row.inheritable)):
        raise ValueError('capabilities not empty')


def drop_tools():
    # Remove inherited I/O bitmap permissions too; dropping CAP_SYS_RAWIO
    # alone does not undo permissions previously granted by ioperm.
    libcall('ioperm', 0, 65536, 0)
    os.setgroups([])
    os.setresgid(TOOL_UID, TOOL_UID, TOOL_UID)
    os.setresuid(TOOL_UID, TOOL_UID, TOOL_UID)
    zero_caps()
    harden()
    if (os.getresuid() != (TOOL_UID,) * 3 or
            os.getresgid() != (TOOL_UID,) * 3 or os.getgroups()):
        raise ValueError('tools privilege drop incomplete')


def bootstrap():
    # No input, output, filesystem mutation or child before this guest guard.
    if (os.getppid() != 1 or os.getresuid() != (0, 0, 0) or
            os.getresgid() != (0, 0, 0) or len(sys.argv) != 1 or
            not (sys.flags.isolated and sys.flags.no_site and
                 sys.flags.dont_write_bytecode)):
        raise ValueError('tools PID1 child required')
    harden()
    directory = os.lstat('/run/tools')
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or
            directory.st_gid != 0 or directory.st_mode & 0o022):
        raise ValueError('private tools directory required')
    # This child receives neither the console nor a PTY. Its wrapper grants
    # only fixed ports, then irreversibly becomes the distinct UID1001 before
    # the existing C service opens its guest-private loopback listener.
    helper = subprocess.Popen(['/usr/local/bin/paos-tools-connect', '--serve'],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
                              env=BASE_ENV)
    os.chown('/run/tools', TOOL_UID, TOOL_UID)
    os.chmod('/run/tools', 0o700)
    drop_tools()
    os.chdir('/run/tools')
    os.umask(0o077)
    ready(helper)
    return helper


def current(helper):
    if helper.poll() is not None:
        raise OSError('CONNECT child ended')


def ready(helper):
    # Only the fixed C wrapper writes this byte, after privilege drop and a
    # successful loopback listen. No console input precedes readiness.
    deadline = time.monotonic() + 5
    try:
        while time.monotonic() < deadline:
            current(helper)
            if select.select([helper.stdout], [], [], 0.1)[0]:
                if os.read(helper.stdout.fileno(), 2) != b'R':
                    raise OSError('CONNECT startup refused')
                return
        raise OSError('CONNECT startup timeout')
    finally:
        helper.stdout.close()


def choose(helper):
    # A single bounded command name, no argument, shell, PATH or script lookup.
    line = bytearray()
    while len(line) < 33:
        current(helper)
        if not select.select([0], [], [], 0.1)[0]:
            continue
        data = os.read(0, 1)
        if not data:
            raise EOFError('console ended')
        if data == b'\n':
            if line not in (b'claude', b'codex'):
                raise ValueError('named CLI required')
            return '/opt/paos-cli/' + line.decode('ascii')
        line.extend(data)
    raise ValueError('command bound')


def attach_tty():
    # Runs in the already unprivileged CLI child after Popen's setsid/dup2.
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def resize(master):
    size = fcntl.ioctl(0, termios.TIOCGWINSZ, b'\0' * 8)
    fcntl.ioctl(master, termios.TIOCSWINSZ, size)


def relay(master, child, helper):
    # Bounded queues and nonblocking writes in both directions. No tool or
    # helper message can extend a START, respawn a child, or select a route.
    to_tool = bytearray()
    to_console = bytearray()
    limit = 65536
    last_size = None
    while True:
        current(helper)
        size = fcntl.ioctl(0, termios.TIOCGWINSZ, b'\0' * 8)
        if size != last_size:
            fcntl.ioctl(master, termios.TIOCSWINSZ, size)
            last_size = size
        readable = ([0] if len(to_tool) < limit and child.poll() is None else [])
        if len(to_console) < limit:
            readable.append(master)
        writable = ([master] if to_tool else []) + ([1] if to_console else [])
        ready, write_ready, _ = select.select(readable, writable, [], 0.1)
        for fd in ready:
            try:
                data = os.read(fd, min(4096, limit - len(to_tool if fd == 0 else to_console)))
            except BlockingIOError:
                continue
            except OSError as exc:
                if fd == master and exc.errno == errno.EIO:
                    data = b''
                else:
                    raise
            if not data:
                if fd == master:
                    # Pending final output drains before the broker exits.
                    while to_console:
                        current(helper)
                        if select.select([], [1], [], 0.1)[1]:
                            try:
                                count = os.write(1, to_console)
                            except BlockingIOError:
                                continue
                            if count <= 0:
                                raise OSError('console write stopped')
                            del to_console[:count]
                    return child.wait(timeout=1)
                raise EOFError('console ended')
            (to_tool if fd == 0 else to_console).extend(data)
        for fd in write_ready:
            queue = to_tool if fd == master else to_console
            try:
                count = os.write(fd, queue)
            except BlockingIOError:
                continue
            if count <= 0:
                raise OSError('PTY write stopped')
            del queue[:count]


def run_tool(program, helper):
    if program not in ('/opt/paos-cli/claude', '/opt/paos-cli/codex'):
        raise ValueError('fixed executable required')
    current(helper)
    master, slave = os.openpty()
    attributes = termios.tcgetattr(0)
    flags = fcntl.fcntl(0, fcntl.F_GETFL)
    try:
        resize(master)
        environment = BASE_ENV | {'HOME': '/run/tools', 'TMPDIR': '/run/tools',
                                  'TERM': 'xterm-256color',
                                  'HTTPS_PROXY': 'http://127.0.0.1:3128',
                                  'HTTP_PROXY': 'http://127.0.0.1:3128',
                                  'ALL_PROXY': 'http://127.0.0.1:3128'}
        child = subprocess.Popen([program], stdin=slave, stdout=slave, stderr=slave,
                                 close_fds=True, start_new_session=True,
                                 preexec_fn=attach_tty, env=environment)
        os.close(slave)
        slave = -1
        tty.setraw(0)
        os.set_blocking(0, False)
        os.set_blocking(master, False)
        return relay(master, child, helper)
    finally:
        if slave >= 0:
            os.close(slave)
        os.close(master)
        fcntl.fcntl(0, fcntl.F_SETFL, flags)
        termios.tcsetattr(0, termios.TCSANOW, attributes)
        # PID1 tears down descendants on this original broker's exit. Never
        # wait/restart after a failed lifecycle, or grant a child a new START.


def main():
    try:
        helper = bootstrap()
        current(helper)
        program = choose(helper)
        return run_tool(program, helper)
    except (OSError, ValueError, EOFError, subprocess.SubprocessError):
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
