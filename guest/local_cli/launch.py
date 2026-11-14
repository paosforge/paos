#!/usr/bin/python3
"""Bounded guest-only direct interactive CLI launch on an inherited Terminal.

No native START/STOP, network setup, authentication, provider selection, runner,
package discovery, or grading. The original parent must join guest claims to its
signed profile/current START/session and continuing PaOS Terminal observations.
"""
import argparse
import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import struct
import termios
import time
import tty

SCHEMA = 'paos.guest-local-cli.v1'
MAX_BINARY = 512 << 20  # Reader extent, not a profile RAM requirement.
QUEUE = 65536


def multiline_request(program, nonce):
    need(program in ('claude','codex') and type(nonce) is str and
         re.fullmatch('[0-9a-f]{16}',nonce) and nonce != '0'*16, 'multiline nonce')
    # Public fixed text only. LF is inside the advertised bracketed paste;
    # DEL removes the deliberate X, then one CR requests submission.
    return (b'\x1b[200~Read this two-line request.\nReply with paos-multiline '+
            program.encode()+b' '+nonce.encode()+b'X\x1b[201~\x7f\r')


def effect_request(program, nonce):
    need(program in ('claude','codex') and type(nonce) is str and
         re.fullmatch('[0-9a-f]{16}',nonce) and nonce != '0'*16, 'effect nonce')
    content = ('paos-local-effect %s %s\n'%(program,nonce)).encode('ascii')
    prompt = (b'Create receipt.txt with exactly this one line: '+content.rstrip(b'\n')+
              b'\nUse your local file tool in the current directory. Do not change any other files.\n')
    # One line submitted to the real interactive UI; no permission/auth answers.
    return content, prompt.replace(b'\n',b' ').rstrip()+b'\r'


def read_effect(directory):
    """Read only the requested fresh scratch leaf, never follow CLI-created links."""
    fd = os.open('receipt.txt',os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,dir_fd=directory)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
             before.st_nlink == 1 and 0 < before.st_size <= 512, 'unsafe effect file')
        data = os.read(fd,513)
        need(len(data) == before.st_size and identity(before) == identity(os.fstat(fd)), 'changed effect file')
        return data
    finally: os.close(fd)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def open_regular(path, maximum):
    """Walk an absolute canonical path without following user-controlled links."""
    p = Path(path)
    need(p.is_absolute() and str(p) == str(path) and '..' not in p.parts, 'canonical absolute path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in p.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        result = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    finally:
        os.close(fd)
    s = os.fstat(result)
    if not stat.S_ISREG(s.st_mode) or not 0 < s.st_size <= maximum:
        os.close(result)
        raise ValueError('regular bounded file required')
    return result


def read_small(path, maximum=16384):
    fd = open_regular(path, maximum)
    try:
        data = os.read(fd, maximum+1)
        need(len(data) == os.fstat(fd).st_size and len(data) <= maximum, 'changed input')
        return data
    finally:
        os.close(fd)


def no_duplicates(pairs):
    value = {}
    for k,v in pairs:
        need(k not in value, 'duplicate JSON key')
        value[k] = v
    return value


def read_manifest(path, program):
    v = json.loads(read_small(path), object_pairs_hook=no_duplicates)
    need(type(v) is dict and set(v) == {'schema','programs'} and v['schema'] == 'paos.local-clis.v1', 'manifest schema')
    need(type(v['programs']) is dict and set(v['programs']) == {'claude','codex'}, 'both explicit program pins required')
    for p in v['programs'].values():
        need(type(p) is dict and set(p) == {'version','executable','size','sha256','origin'}, 'program fields')
        for key in ('version','origin'):
            need(type(p[key]) is str and 0 < len(p[key]) <= 256 and all(32 <= ord(c) < 127 for c in p[key]), 'program label')
        need(type(p['size']) is int and 64 <= p['size'] <= MAX_BINARY, 'program extent')
        need(type(p['sha256']) is str and re.fullmatch('[0-9a-f]{64}',p['sha256']), 'program digest')
        need(type(p['executable']) is str and len(p['executable']) <= 1024, 'program path')
    return dict(name=program, **v['programs'][program])


def identity(s):
    return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def hash_fd(fd):
    h = hashlib.sha256(); at = 0
    while True:
        b = os.pread(fd,1<<20,at)
        if not b: return h.hexdigest()
        h.update(b); at += len(b)
        need(at <= MAX_BINARY, 'executable grew')


def open_program(pin):
    fd = open_regular(pin['executable'], MAX_BINARY)
    try:
        before = os.fstat(fd)
        need(before.st_mode & 0o111 and not before.st_mode & 0o022, 'executable mode')
        header = os.pread(fd,64,0)
        need(header[:7] == b'\x7fELF\x02\x01\x01' and len(header) == 64 and
             struct.unpack_from('<H',header,16)[0] in (2,3) and
             struct.unpack_from('<H',header,18)[0] == 62, 'actual x86-64 ELF required, no script/wrapper')
        need(before.st_size == pin['size'] and hash_fd(fd) == pin['sha256'] and
             identity(before) == identity(os.fstat(fd)), 'executable differs from pin')
        return fd
    except BaseException:
        os.close(fd); raise


def read_binding(path):
    data = read_small(path,4096).decode('ascii')
    value = {}
    for line in data.splitlines():
        k,sep,v = line.partition('=')
        need(sep and k not in value, 'malformed/duplicate guest binding')
        value[k] = v
    need(set(value) == {'bdf','start','nonce','physical_bdf','physical_interface','relay'}, 'guest binding fields')
    for key in ('bdf','physical_bdf'):
        need(re.fullmatch(r'0000:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]',value[key]), 'BDF')
    need(re.fullmatch('[1-9][0-9]{0,9}',value['start']) and int(value['start']) <= 4294967295, 'START')
    need(re.fullmatch('[0-9a-f]{16}',value['nonce']) and value['nonce'] != '0'*16, 'nonce')
    for key in ('physical_interface','relay'):
        need(re.fullmatch('[a-zA-Z0-9_.-]{1,32}',value[key]), 'interface')
    need(value['physical_interface'] != value['relay'], 'interface collision')
    value['start'] = int(value['start'])
    return value


def open_evidence(path):
    p = Path(path)
    need(p.is_absolute() and str(p) == str(path) and '..' not in p.parts, 'canonical evidence path')
    parent = os.open('/',os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in p.parts[1:-1]:
            child = os.open(part,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,dir_fd=parent)
            os.close(parent); parent = child
        # No parent symlink race; exclusive mkdir relative to the held directory.
        os.mkdir(p.name,mode=0o700,dir_fd=parent)
        return os.open(p.name,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,dir_fd=parent)
    finally:
        os.close(parent)


def create(directory, name):
    return os.open(name,os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,0o600,dir_fd=directory)


def write_all(fd, data):
    while data:
        n = os.write(fd,data)
        need(n > 0,'short evidence write')
        data = data[n:]


def json_bytes(v):
    return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')


def start_ticks(pid):
    # comm can contain spaces or parentheses; field22 follows the final ')'.
    return int(Path('/proc/%d/stat'%pid).read_text().rsplit(')',1)[1].split()[19])


def descendants():
    pending = [os.getpid()]; found = {}
    while pending:
        pid = pending.pop()
        try:
            children = Path('/proc/%d/task/%d/children'%(pid,pid)).read_text().split()
        except FileNotFoundError:
            continue
        for p in children:
            child = int(p)
            if child in found: continue
            try: found[child] = start_ticks(child)
            except (FileNotFoundError, ProcessLookupError): continue
            pending.append(child)
    return found


def signal_descendants(sig):
    for pid,ticks in descendants().items():
        try:
            if start_ticks(pid) == ticks: os.kill(pid,sig)
        except ProcessLookupError:
            pass


def reap():
    results = {}
    while True:
        try: pid,status = os.waitpid(-1,os.WNOHANG)
        except ChildProcessError: break
        if not pid: break
        results[pid] = os.waitstatus_to_exitcode(status)
    return results


def prctl(option, value):
    libc = ctypes.CDLL(None,use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(option,value,0,0,0): raise OSError(ctypes.get_errno(),'prctl')


def proc_bytes(path,maximum):
    with open(path,'rb') as f:data=f.read(maximum+1)
    need(len(data)<=maximum,'bounded process observation')
    return data


def executable_observation(fd):
    before = os.fstat(fd)
    digest = hash_fd(fd)
    need(identity(before) == identity(os.fstat(fd)), 'changed observed executable')
    return dict(zip(('device','inode','size','mtime_ns','ctime_ns'),identity(before)),sha256=digest)


def version_observation(binary, pin, cutoff):
    """Bounded same-held-ELF version mode, inside the original launch deadline.

    No shell, provider request, config read, auth action or replacement binary.
    The interactive invocation remains separate and receives no CLI arguments.
    """
    observation = dict(argument='--version',program_sha256=pin['sha256'],
                       status='unobserved',output_hex='',exit_code=None,cleanup_complete=True,
                       executable=executable_observation(binary))
    end = min(cutoff,time.monotonic()+1)
    if end-time.monotonic() < 0.1:return observation
    rd,wr = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    pid = None;data = bytearray();status = None
    try:
        parent = os.getpid();pid = os.fork()
        if pid == 0:
            try:
                os.close(rd);os.setsid();prctl(1,signal.SIGKILL)
                if os.getppid() != parent:os._exit(125)
                null = os.open('/dev/null',os.O_RDONLY | os.O_CLOEXEC)
                os.dup2(null,0);os.dup2(wr,1);os.dup2(wr,2)
                # A blocking child writer, bounded by the parent's read limit.
                fcntl.fcntl(1,fcntl.F_SETFL,fcntl.fcntl(1,fcntl.F_GETFL) & ~os.O_NONBLOCK)
                os.execve(binary,[pin['name'],'--version'],os.environ.copy())
            except BaseException:os._exit(126)
        os.close(wr);wr = -1
        observation['status'] = 'timeout'
        while time.monotonic() < end:
            ready = select.select([rd],[],[],min(0.02,max(0,end-time.monotonic())))[0]
            if ready:
                block = os.read(rd,513-len(data));data.extend(block)
                if len(data)>512:
                    observation['status']='output_limit';break
            if status is None:
                done,value = os.waitpid(pid,os.WNOHANG)
                if done:status = value
            if ready and not block and status is not None:
                observation.update(status='recorded',exit_code=os.waitstatus_to_exitcode(status));break
    finally:
        if wr >= 0:os.close(wr)
        os.close(rd)
        if pid is not None:
            # Version mode is not allowed to leave workers behind. The launcher
            # is already a subreaper; no interactive child exists at this point.
            signal_descendants(signal.SIGKILL)
            until = time.monotonic()+0.2
            while time.monotonic()<until:
                reap()
                if not descendants():break
                time.sleep(0.005)
            observation['cleanup_complete'] = not descendants()
    need(executable_observation(binary)==observation['executable'], 'changed version executable')
    observation['output_hex'] = bytes(data[:512]).hex()
    return observation


def credential_missing_observation(binary, pin, cutoff, directory, evidence, nonce, stop):
    """One opt-in original CLI status query with a fresh empty configuration.

    Never log in, log out, request a model, answer a prompt, inherit credential
    variables, or forward status output to Terminal. Only strictly public
    negative bytes may enter the fixed private receipt. This is not proof of
    request refusal, successful authentication, approval, or secret redaction.
    """
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{16}', nonce) and nonce != '0'*16,
         'missing-auth nonce')
    arguments = (['claude','auth','status','--json'] if pin['name'] == 'claude' else
                 ['codex','-c','cli_auth_credentials_store="file"','login','status'])
    os.mkdir('missing-credentials', mode=0o700, dir_fd=directory)
    config = os.open('missing-credentials', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory)
    home = str(evidence/'missing-credentials')
    environment = {key:home for key in ('HOME','CODEX_HOME','CLAUDE_CONFIG_DIR','XDG_CONFIG_HOME',
                                       'XDG_DATA_HOME','XDG_CACHE_HOME')}
    environment.update(PATH='/usr/bin:/bin', LANG='C', TERM='dumb',
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1', DISABLE_AUTOUPDATER='1')
    observation = dict(schema='paos.cli-missing-credentials.v1', nonce=nonce,
        arguments=arguments, program_sha256=pin['sha256'], executable=executable_observation(binary),
        home=home, uid=os.getuid(), config_mode=stat.S_IMODE(os.fstat(config).st_mode),
        entries_before=os.listdir(config), environment_keys=sorted(environment),
        status='unobserved', output_hex='', exit_code=None, cleanup_complete=True)
    rd = wr = -1; pid = None; data = bytearray(); status = None
    end = min(cutoff, time.monotonic()+1)
    try:
        need(observation['config_mode'] == 0o700 and os.fstat(config).st_uid == os.getuid() and
             not observation['entries_before'], 'missing-auth config custody')
        if stop or end-time.monotonic() < 0.1:return observation
        rd,wr = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        parent = os.getpid();pid = os.fork()
        if pid == 0:
            try:
                os.close(rd);os.setsid();prctl(1,signal.SIGKILL)
                if os.getppid() != parent:os._exit(125)
                for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP,signal.SIGQUIT,signal.SIGWINCH):
                    signal.signal(sig,signal.SIG_DFL)
                os.fchdir(config)
                need(os.getcwd() == home, 'missing-auth config moved')
                null = os.open('/dev/null',os.O_RDONLY | os.O_CLOEXEC)
                os.dup2(null,0);os.dup2(wr,1);os.dup2(wr,2)
                fcntl.fcntl(1,fcntl.F_SETFL,fcntl.fcntl(1,fcntl.F_GETFL) & ~os.O_NONBLOCK)
                for name in os.listdir('/proc/self/fd'):
                    fd = int(name)
                    if fd > 2 and fd != binary:
                        try:os.close(fd)
                        except OSError:pass
                os.execve(binary,arguments,environment)
            except BaseException:os._exit(126)
        os.close(wr);wr = -1
        observation['status'] = 'timeout'
        while not stop and time.monotonic() < end:
            ready = select.select([rd],[],[],min(0.02,max(0,end-time.monotonic())))[0]
            block = None
            if ready:
                block = os.read(rd,4097-len(data));data.extend(block)
                if len(data)>4096:observation['status']='output_limit';break
            if status is None:
                done,value = os.waitpid(pid,os.WNOHANG)
                if done:status = value
            if block == b'' and status is not None:
                observation.update(status='output_withheld',exit_code=os.waitstatus_to_exitcode(status))
                break
    finally:
        for fd in (rd,wr,config):
            if fd >= 0:os.close(fd)
        if pid is not None:
            # No interactive child exists yet; reuse the original subreaper.
            signal_descendants(signal.SIGKILL)
            until = time.monotonic()+0.2
            while time.monotonic()<until:
                reap()
                if not descendants():break
                time.sleep(0.005)
            observation['cleanup_complete'] = not descendants()
        need(executable_observation(binary) == observation['executable'], 'changed missing-auth executable')
    if observation['status'] == 'output_withheld':
        raw = bytes(data)
        public = False
        if pin['name'] == 'codex':
            public = raw == b'Not logged in\n'
            if raw.startswith(b'Logged in using '):observation['status']='authenticated_output_withheld'
        else:
            try:
                value = json.loads(raw,object_pairs_hook=no_duplicates,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite status')))
                if type(value) is dict:
                    if value.get('loggedIn') is True:observation['status']='authenticated_output_withheld'
                    public = ({'loggedIn','authMethod'} <= set(value) <=
                        {'loggedIn','authMethod','apiProvider','analyticsDisabled','projectsDirectory','configDirectory'} and
                        value['loggedIn'] is False and value['authMethod'] == 'none' and
                        value.get('apiProvider','firstParty') in ('firstParty','anthropic') and
                        type(value.get('analyticsDisabled',True)) is bool and
                        all(value.get(k) is None or value[k] in (home,home+'/projects')
                            for k in ('projectsDirectory','configDirectory')))
            except (ValueError,UnicodeError,TypeError):pass
        if public:observation.update(status='recorded',output_hex=raw.hex())
        # A malformed or unexpected response is deliberately not persisted,
        # even in hexadecimal or as a digest, and is never displayed.
    return observation


def forwarded_observation(child,process,data,offset,read_ns):
    """An actual inherited-PTY write, followed by same-child live /proc bytes.

    A child exiting during observation is ordinary missing evidence. This
    neither changes the launch outcome nor asserts model-request progress.
    """
    try:
        raw = proc_bytes('/proc/%d/stat'%child,2048).decode('ascii')
        words = raw.rsplit(')',1)[1].split()
        if (int(raw.split(' ',1)[0]) != child or words[0] in ('Z','X','x') or
                int(words[19]) != process['start_ticks']):
            return None
    except (OSError,ValueError,IndexError,UnicodeError):
        return None
    return dict(event='pty_output_forwarded',process=process,offset=offset,
        bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
        read_monotonic_ns=read_ns,monotonic_ns=time.monotonic_ns(),proc_stat_after=raw)


def interrupt_observation(path,binding,child,observed,master):
    """Guard real Ctrl-C input to the held original foreground child PTY.

    This is a before-write observation, not an atomic write/foreground claim
    and not evidence that a provider request was actually cancelled.
    """
    current = read_binding(path)
    need(current == binding, 'interrupt guest binding changed')
    raw = proc_bytes('/proc/%d/stat'%child,2048).decode('ascii')
    fields = raw.rsplit(')',1)[1].split()
    need(int(raw.split(' ',1)[0]) == observed['pid'] == child and
         int(fields[19]) == observed['start_ticks'] == observed['exec_start_ticks'] and
         int(fields[2]) == observed['process_group'] == child and
         int(fields[3]) == observed['session'] == child and
         fields[0] in ('R','S','D','T','t','K','W','P','I'), 'interrupt child changed')
    foreground = os.tcgetpgrp(master)
    need(foreground == observed['process_group'], 'interrupt foreground changed')
    attrs = termios.tcgetattr(master)
    vintr = attrs[6][termios.VINTR]
    return dict(process=observed,binding=current,foreground=foreground,proc_stat_before=raw,
                checked_ns=time.monotonic_ns(),isig=bool(attrs[3] & termios.ISIG),
                vintr=vintr if type(vintr) is int else vintr[0])

def keyboard_owner(args, master, process, opened, binding):
    """Guard the original keyboard operation; C7 keeps its generic interrupt guard."""
    pid=process['pid']
    need(read_binding(args.binding)==binding and start_ticks(pid)==process['start_ticks'] and
         os.getsid(pid)==process['session'] and os.getpgid(pid)==process['process_group'] and
         os.tcgetpgrp(master)==pid, 'keyboard original ownership changed')
    actual=os.open('/proc/%d/exe'%pid,os.O_RDONLY | os.O_CLOEXEC)
    try:
        want=tuple(opened[k] for k in ('device','inode','size','mtime_ns','ctime_ns'))
        need(identity(os.fstat(actual))==want, 'keyboard original executable changed')
    finally:os.close(actual)


def resize_observation(binding_path, binding, master, process, boot, sequence):
    """Kernel PTY observation only; native window/request belong to the parent.

    A completed ioctl is not evidence that the child consumed SIGWINCH or
    redrew. If the original process exits during observation, omit the receipt.
    """
    def live_stat():
        raw = proc_bytes('/proc/%d/stat'%process['pid'],2048).decode('ascii')
        words = raw.rsplit(')',1)[1].split()
        need(int(raw.split(' ',1)[0]) == process['pid'] and
             int(words[19]) == process['start_ticks'] and
             int(words[2]) == process['process_group'] and int(words[3]) == process['session'],
             'resize original process changed')
        if words[0] in ('Z','X','x'):raise ProcessLookupError()
        return raw
    need(read_binding(binding_path) == binding, 'resize original binding changed')
    try:
        before = live_stat()
        observed_ns = time.monotonic_ns()
        window = fcntl.ioctl(0,termios.TIOCGWINSZ,b'\0'*8)
        fcntl.ioctl(master,termios.TIOCSWINSZ,window)
        applied_ns = time.monotonic_ns()
        readback = fcntl.ioctl(master,termios.TIOCGWINSZ,b'\0'*8)
        after = live_stat()
        foreground = os.tcgetpgrp(master)
    except (FileNotFoundError,ProcessLookupError):return None
    need(read_binding(binding_path) == binding and readback == window,
         'resize binding or geometry changed')
    rows,columns = struct.unpack('HHHH',window)[:2]
    got_rows,got_columns = struct.unpack('HHHH',readback)[:2]
    return dict(event='resize',schema='paos.cli-resize.v1',sequence=sequence,
        kind='initial' if sequence == 1 else 'sigwinch',source='inherited_terminal',
        process=process,binding=binding,guest_boot_id=boot,
        proc_stat_before=before,proc_stat_after=after,foreground_process_group=foreground,
        observed_ns=observed_ns,applied_ns=applied_ns,monotonic_ns=time.monotonic_ns(),
        rows=rows,columns=columns,readback_rows=got_rows,readback_columns=got_columns)


def run(args):
    began = time.monotonic(); directory = open_evidence(args.evidence)
    raw = events = binary = master = work = -1
    prompt = b''; prompt_sent = 0; prompt_pending = False
    multiline = getattr(args,'multiline_nonce',None)
    prompt_context = None
    keyboard = getattr(args,'keyboard_nonce',None)
    keyboard_received = 0; keyboard_control = bytearray(); keyboard_offered = False
    editor_output = bytearray(); editor_offset = None; editor_lflag = None; input_began_ns = None
    saved = None; old_flags = {}; old_handlers = {}; child = None
    observed = {}; stop = []; resized = []; reaped = {}; total = 0
    resize_sequence = 0
    forwarded = 0; forwarding_samples = 0; pending_sample = None
    interrupt_recorded = False
    result = dict(schema=SCHEMA,grade='UNOBSERVED',reason='refused',process=None,program=None,requested_program=args.program,
                  binding_status='guest_claim_requires_parent_join',remote_model_requests='provider-dependent; not observed by this launcher',
                  cleanup_complete=True,reaped_count=0,terminal_restored=None)
    try:
        raw = create(directory,'output.bin'); events = create(directory,'events.jsonl')
        need(os.isatty(0) and os.isatty(1) and os.fstat(0).st_rdev == os.fstat(1).st_rdev and
             os.tcgetpgrp(0) == os.getpgrp(), 'inherited foreground Terminal required')
        need(1 <= args.seconds <= 1800 and 1024 <= args.output_limit <= 64 << 20, 'launch bound')
        pin = read_manifest(args.manifest,args.program)
        result['binding'] = read_binding(args.binding)
        binary = open_program(pin); result['program'] = pin
        need(sum(v is not None for v in (multiline,keyboard,args.effect_nonce))<=1, 'distinct CLI operations')
        if multiline is not None:
            import paos_cli_prompt
            prompt = multiline_request(args.program,multiline)
            result['multiline'] = dict(schema='paos.cli-multiline-input.v1',nonce=multiline,
                input_hex=prompt.hex(),written_bytes=0,status='waiting_for_editor')
        if args.effect_nonce is not None or keyboard is not None:
            effect_nonce = keyboard if keyboard is not None else args.effect_nonce
            content,prompt = effect_request(args.program,effect_nonce)
            os.mkdir('work',mode=0o700,dir_fd=directory)
            work = os.open('work',os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,dir_fd=directory)
            result['effect'] = dict(schema='paos.local-cli-effect.v1',nonce=effect_nonce,
                file='receipt.txt',cwd=str(args.evidence/'work'),initially_absent=True,
                prompt_sha256=hashlib.sha256(prompt).hexdigest(),prompt_bytes=len(prompt),
                prompt_delivered=False,status='absent',readback_bytes=0)
        if keyboard is not None:
            result['keyboard'] = dict(schema='paos.cli-keyboard.v1',source='inherited_terminal_stdin',
                nonce=keyboard,ready=False,received_bytes=0)
        result['guest_boot_id'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        result['uid'] = os.getuid(); result['cwd'] = os.getcwd()
        prctl(36,1)  # Linux child subreaper: collect double-fork/new-session descendants.
        version = version_observation(binary,pin,began+args.seconds)
        need(version['cleanup_complete'], 'version descendants still active')
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP,signal.SIGQUIT):
            old_handlers[sig] = signal.signal(sig,lambda s,f:stop.append(s))
        old_handlers[signal.SIGWINCH] = signal.signal(signal.SIGWINCH,lambda s,f:resized.append(True))
        if getattr(args,'credentials_missing_nonce',None) is not None:
            result['credentials_missing'] = credential_missing_observation(binary,pin,began+args.seconds,
                directory,args.evidence,args.credentials_missing_nonce,stop)
            need(result['credentials_missing']['cleanup_complete'], 'missing-auth descendants still active')
            need(not stop, 'missing-auth interrupted')
        err_r,err_w = os.pipe2(os.O_CLOEXEC)
        parent = os.getpid()
        inherited_termios = termios.tcgetattr(0)
        inherited_window = fcntl.ioctl(0,termios.TIOCGWINSZ,b'\0'*8)
        child,master = os.forkpty()
        if child == 0:
            try:
                if work >= 0: os.fchdir(work)
                os.close(err_r)
                termios.tcsetattr(0,termios.TCSANOW,inherited_termios)
                fcntl.ioctl(0,termios.TIOCSWINSZ,inherited_window)
                prctl(1,signal.SIGKILL)  # A dead launcher must not leave the direct CLI alive.
                if os.getppid() != parent: os._exit(125)
                for sig in old_handlers: signal.signal(sig,signal.SIG_DFL)
                for name in os.listdir('/proc/self/fd'):
                    fd = int(name)
                    if fd > 2 and fd not in (binary,err_w):
                        try: os.close(fd)
                        except OSError: pass
                # No shell, --version, print mode, auth flags or alternate executable.
                environment = os.environ.copy()
                environment.pop('PAOS_CLI_PROMPT_CONTEXT',None)
                if multiline is not None:
                    environment[paos_cli_prompt.ENV] = str(args.evidence/paos_cli_prompt.CONTEXT)
                os.execve(binary,[pin['name']],environment)
            except BaseException:
                os.write(err_w,b'exec_refused\n'); os._exit(126)
        os.close(err_w)
        try:
            need(select.select([err_r],[],[],5)[0], 'exec handshake timeout')
            need(os.read(err_r,128) == b'', 'exec failed')
        finally:
            os.close(err_r)
        # Confirm the actual kernel /proc exe inode and bytes, rather than argv labels.
        raw_before = proc_bytes('/proc/%d/stat'%child,2048).decode('ascii')
        ticks = int(raw_before.rsplit(')',1)[1].split()[19])
        actual = os.open('/proc/%d/exe'%child,os.O_RDONLY | os.O_CLOEXEC)
        try:
            opened = executable_observation(binary);running = executable_observation(actual)
            need(opened == running and running['sha256'] == pin['sha256'], 'running exe differs')
        finally:
            os.close(actual)
        observed = dict(pid=child,start_ticks=ticks,exec_start_ticks=start_ticks(child),
                        executable=os.readlink('/proc/%d/exe'%child),session=os.getsid(child),process_group=os.getpgid(child))
        need(observed['start_ticks'] == observed['exec_start_ticks'] and observed['session'] == child and
             observed['process_group'] == child, 'child identity/session changed')
        raw_after = proc_bytes('/proc/%d/stat'%child,2048).decode('ascii')
        result['identity'] = dict(schema='paos.cli-process-identity.v1',
            proc_stat_before=raw_before,proc_stat_after=raw_after,
            cmdline_hex=proc_bytes('/proc/%d/cmdline'%child,256).hex(),
            boot_id_raw=proc_bytes('/proc/sys/kernel/random/boot_id',64).decode('ascii'),
            opened_executable=opened,running_executable=running,version=version)
        result['process'] = observed
        if keyboard is not None:result['keyboard']['process'] = observed
        if work >= 0: result['effect']['process'] = observed
        write_all(events,json_bytes(dict(event='exec_observed',monotonic_ns=time.monotonic_ns(),process=observed)))
        if multiline is not None:
            prompt_context = paos_cli_prompt.prepare(directory,args.program,multiline,observed,opened,
                result['binding'],args.binding,result['guest_boot_id'],int((began+args.seconds)*1_000_000_000))
        saved = termios.tcgetattr(0)
        # PTY was created before raw mode: its child keeps the normal interactive discipline.
        tty.setraw(0,termios.TCSANOW)
        for fd in (0,1,master):
            old_flags[fd] = fcntl.fcntl(fd,fcntl.F_GETFL)
            fcntl.fcntl(fd,fcntl.F_SETFL,old_flags[fd] | os.O_NONBLOCK)
        resized.append(True)
        outgoing = bytearray(); incoming = bytearray(); eof = False
        result['reason'] = 'child_exit'
        while True:
            reaped.update(reap())
            if stop:
                result['reason'] = 'signal'; result['cancel_signal'] = stop[0]; break
            if time.monotonic()-began >= args.seconds:
                result['reason'] = 'deadline'; break
            if resized:
                resized.clear()
                if child not in reaped:
                    event = resize_observation(args.binding,result['binding'],master,observed,
                        result['guest_boot_id'],resize_sequence+1)
                    if event is not None:
                        resize_sequence += 1
                        write_all(events,json_bytes(event))
            if child in reaped and eof and not outgoing: break
            readers = ([] if eof or len(outgoing) >= QUEUE else [master])
            if child not in reaped and len(incoming) < QUEUE and (
                (keyboard is not None and result['keyboard']['ready'] and keyboard_received<len(prompt)) or
                (keyboard is None and (not prompt or prompt_sent == len(prompt)))): readers.append(0)
            writers = ([1] if outgoing or keyboard_control else [])+([master] if incoming and not eof else [])
            ready,writeable,_ = select.select(readers,writers,[],0.05)
            if master in ready:
                try: data = os.read(master,min(8192,QUEUE-len(outgoing)))
                except OSError as e:
                    if e.errno == errno.EIO: data = b''
                    elif e.errno in (errno.EAGAIN,errno.EINTR): continue
                    else: raise
                if not data: eof = True
                else:
                    if total+len(data) > args.output_limit:
                        result['reason'] = 'output_limit'; break
                    # At most two different PTY reads, each begun after the
                    # previous sampled write. Never infer arrivals by splitting
                    # one buffered write or enlarge the original deadline.
                    if forwarding_samples < 2 and pending_sample is None and not outgoing:
                        pending_sample = (total,data[:512],time.monotonic_ns())
                    write_all(raw,data); total += len(data); outgoing.extend(data)
                    if multiline is not None:
                        editor_output.extend(data)
                    if multiline is not None and not prompt_pending:
                        # Both observations belong to the actual held child PTY.
                        # No banner/echo or advertised support earns received-prompt credit.
                        flags = termios.tcgetattr(master)[3]
                        enables = editor_output.rfind(b'\x1b[?2004h')
                        editor_ready = (enables >= 0 and enables > editor_output.rfind(b'\x1b[?2004l') and
                                 not flags & (termios.ICANON | termios.ECHO))
                        if editor_ready:
                            editor_offset = enables; editor_lflag = flags
                    if keyboard is not None and not keyboard_offered:
                        keyboard_owner(args,master,observed,opened,result['binding'])
                        keyboard_control.extend(('LCKEY1 %s %s %d %d\n'%(keyboard,args.program,child,observed['start_ticks'])).encode())
                        keyboard_offered = True; prompt_pending = True
                    if prompt and keyboard is None and not prompt_pending and (multiline is None or editor_offset is not None):
                        # Input goes only to this verified child PTY after its first
                        # actual output. It can never fall through to the guest shell.
                        need(start_ticks(child) == observed['start_ticks'] and
                             os.tcgetpgrp(master) == child, 'effect process ownership changed')
                        incoming.extend(prompt); prompt_pending = True
            if 0 in ready:
                try: data = os.read(0,min(8192,QUEUE-len(incoming)))
                except BlockingIOError: data = None
                if data == b'': result['reason'] = 'terminal_eof'; break
                if data:
                    if b'\x03' in data:
                        interrupt_observation(args.binding,result['binding'],child,observed,master)

                    if keyboard is not None:
                        keyboard_owner(args,master,observed,opened,result['binding'])
                        need(data==prompt[keyboard_received:keyboard_received+len(data)], 'unexpected keyboard input')
                        keyboard_received += len(data)
                        result['keyboard']['received_bytes'] = keyboard_received
                    incoming.extend(data)  # Never save arbitrary input or credentials.
            if 1 in writeable and not outgoing and keyboard_control:
                keyboard_owner(args,master,observed,opened,result['binding'])
                try: count=os.write(1,keyboard_control)
                except BlockingIOError: count=0
                del keyboard_control[:count]
                if not keyboard_control:
                    result['keyboard']['ready'] = True
                    write_all(events,json_bytes(dict(event='keyboard_ready',process=observed,nonce=keyboard,monotonic_ns=time.monotonic_ns())))
                writeable.remove(1)  # Control bytes are never child-output forwarding bytes.
            for fd,queue in ((1,outgoing),(master,incoming)):
                if fd in writeable:
                    if fd == master and keyboard is not None:
                        keyboard_owner(args,master,observed,opened,result['binding'])
                    if fd == master and multiline is not None:
                        need(start_ticks(child) == observed['start_ticks'] and
                             os.tcgetpgrp(master) == child, 'multiline process ownership changed')
                        if prompt_sent < len(prompt):
                            editor_lflag = termios.tcgetattr(master)[3]
                            editor_offset = editor_output.rfind(b'\x1b[?2004h')
                            need(not editor_lflag & (termios.ICANON | termios.ECHO) and
                                 editor_offset >= 0 and editor_offset > editor_output.rfind(b'\x1b[?2004l'),
                                 'multiline editor mode changed')
                        if input_began_ns is None: input_began_ns = time.monotonic_ns()
                    interrupt = None
                    if fd == master and b'\x03' in queue:
                        # A queued control may outlive its ingress check. Guard
                        # every delivery attempt, including after a short write.
                        interrupt = interrupt_observation(args.binding,result['binding'],child,observed,master)
                    try: count = os.write(fd,queue)
                    except BlockingIOError: continue
                    except OSError as e:
                        if fd == master and e.errno == errno.EIO: incoming.clear(); continue
                        raise
                    if interrupt is not None and not interrupt_recorded:
                        controls = queue[:count].count(3)
                        if controls:
                            interrupt.update(event='pty_interrupt_written',interrupt_bytes=controls,
                                             monotonic_ns=time.monotonic_ns())
                            write_all(events,json_bytes(interrupt)); interrupt_recorded = True
                    del queue[:count]
                    if fd == 1:
                        forwarded += count
                        if pending_sample is not None:
                            offset,data,read_ns = pending_sample
                            if forwarded >= offset+len(data):
                                event = forwarded_observation(child,observed,data,offset,read_ns)
                                if event is not None:
                                    write_all(events,json_bytes(event)); forwarding_samples += 1
                                pending_sample = None
                    if fd == master and prompt_pending and prompt_sent < len(prompt):
                        prompt_sent += min(count,len(prompt)-prompt_sent)
                        if multiline is not None:
                            result['multiline'].update(written_bytes=prompt_sent,status='partial')
                        if prompt_sent == len(prompt):
                            if multiline is not None:
                                result['multiline']['status'] = 'delivered'
                                event = forwarded_observation(child,observed,prompt,0,input_began_ns)
                                if event is not None:
                                    event.update(event='multiline_input_delivered',nonce=multiline,editor_offset=editor_offset,
                                                 editor_lflag=editor_lflag,output_bytes_before_write=total)
                                    write_all(events,json_bytes(event))
                            else:
                                result['effect']['prompt_delivered'] = True
                                write_all(events,json_bytes(dict(event='effect_prompt_delivered',process=observed,
                                    bytes=len(prompt),sha256=hashlib.sha256(prompt).hexdigest(),monotonic_ns=time.monotonic_ns())))
    except (OSError,ValueError,TypeError,KeyError) as error:
        # Fixed diagnostics only: no argv, environment, provider config or exception text.
        result['reason'] = 'refused'
        result['error_type'] = type(error).__name__
    finally:
        result['output_forwarding_closed_ns'] = time.monotonic_ns()
        if child is not None:
            # Also covers exec/identity refusal and grandchildren that created new sessions.
            signal_descendants(signal.SIGTERM)
            until = time.monotonic()+0.3
            while time.monotonic() < until:
                reaped.update(reap())
                if not descendants(): break
                time.sleep(0.01)
            signal_descendants(signal.SIGKILL)
            until = time.monotonic()+2
            while time.monotonic() < until:
                reaped.update(reap())
                if not descendants(): break
                signal_descendants(signal.SIGKILL)
                time.sleep(0.01)
            reaped.update(reap())
            remaining = descendants()
            result['cleanup_complete'] = not remaining
            result['reaped_count'] = len(reaped)
            if child in reaped:
                result['exit_code'] = reaped[child] if reaped[child] >= 0 else 128-reaped[child]
            if observed:
                result['retirement'] = dict(process=observed,binding=result['binding'],
                    monotonic_ns=time.monotonic_ns(),cleanup_complete=not remaining,
                    remaining=[dict(pid=p,start_ticks=t) for p,t in sorted(remaining.items())[:32]],
                    remaining_count=len(remaining),reaped=dict(sorted(reaped.items())[:32]),
                    reaped_count=len(reaped),reaped_truncated=len(reaped)>32,child_status=reaped.get(child))
        if work >= 0:
            data = b''
            try:
                need(result['cleanup_complete'], 'effect descendants still active')
                data = read_effect(work); result['effect']['status'] = 'read'
            except FileNotFoundError: pass
            except (OSError,ValueError): result['effect']['status'] = 'refused'
            result['effect']['readback_bytes'] = len(data)
            try:
                out = create(directory,'effect.bin')
                try: write_all(out,data); os.fsync(out)
                finally: os.close(out)
            except OSError:
                result['effect']['status'] = 'refused'
        for fd,flags in old_flags.items():
            try: fcntl.fcntl(fd,fcntl.F_SETFL,flags)
            except OSError: pass
        if saved is not None:
            try:
                termios.tcsetattr(0,termios.TCSANOW,saved)
                result['terminal_restored'] = True
            except (OSError,termios.error):
                # A disconnected controlling tty cannot be restored; still save cleanup.
                result['terminal_restored'] = False
                if result['reason'] == 'child_exit': result['reason'] = 'terminal_lost'
        for sig,handler in old_handlers.items(): signal.signal(sig,handler)
        result.update(output_bytes=total,elapsed_ms=int((time.monotonic()-began)*1000))
        if prompt_context is not None:
            result['prompt_receipt'] = paos_cli_prompt.collect(directory,prompt_context)
            if not result['cleanup_complete']:
                result['prompt_receipt'] = dict(schema=paos_cli_prompt.SCHEMA,status='refused')
        for fd in (raw,events,binary,master,work):
            if fd >= 0:
                if fd in (raw,events): os.fsync(fd)
                os.close(fd)
        try:
            out = create(directory,'result.json')
            try: write_all(out,json_bytes(result)); os.fsync(out)
            finally: os.close(out)
            os.fsync(directory)
        finally: os.close(directory)
    if result['reason'] == 'child_exit' and result['cleanup_complete']:
        return result.get('exit_code',125)
    return 124 if result['reason'] in ('deadline','output_limit') else 125


READOUT_LIMITS = {'result.json':8192, 'events.jsonl':8192, 'output.bin':4096}
READOUT_PAGE = 192


def readout(args):
    """One fixed private artifact set on the same original Terminal, no input tap."""
    need(type(args.nonce) is str and re.fullmatch('[0-9a-f]{16}',args.nonce) and args.nonce != '0'*16, 'readout nonce')
    p = args.evidence
    need(p.is_absolute() and '..' not in p.parts, 'readout directory')
    directory = os.open('/',os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    files = {}
    try:
        for part in p.parts[1:]:
            child = os.open(part,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,dir_fd=directory)
            os.close(directory);directory = child
        st = os.fstat(directory)
        need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700, 'private evidence custody')
        limits = dict(READOUT_LIMITS)
        # Older/non-effect receipts keep the original fixed set.
        try: os.stat('effect.bin',dir_fd=directory,follow_symlinks=False)
        except FileNotFoundError: pass
        else: limits['effect.bin'] = 512
        for name,limit in limits.items():
            # Empty output/events are valid after a launch refusal; result is mandatory.
            fd = os.open(name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,dir_fd=directory)
            try:
                before = os.fstat(fd)
                need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1 and
                     stat.S_IMODE(before.st_mode) == 0o600 and 0 <= before.st_size <= limit, 'private bounded artifact')
                data = os.read(fd,limit+1)
                need(len(data) == before.st_size and identity(before) == identity(os.fstat(fd)), 'changed artifact')
            finally: os.close(fd)
            files[name] = data
    finally: os.close(directory)
    result = json.loads(files['result.json'],object_pairs_hook=no_duplicates)
    need(type(result) is dict and result.get('schema') == SCHEMA and result.get('grade') == 'UNOBSERVED' and
         result.get('requested_program') == args.program, 'artifact program/schema')
    # Validate everything before writing the first frame; partial transport remains partial.
    write_all(1,b'\n')  # The prior CLI may have ended on an unterminated prompt.
    for name,data in files.items():
        count = (len(data)+READOUT_PAGE-1)//READOUT_PAGE
        write_all(1,('LCMETA1 %s %s %s %d %s %d\n' %
                     (args.nonce,args.program,name,len(data),hashlib.sha256(data).hexdigest(),count)).encode('ascii'))
        for page in range(count):
            encoded = base64.b64encode(data[page*READOUT_PAGE:(page+1)*READOUT_PAGE]).decode('ascii')
            write_all(1,('LCD1 %s %s %s %d %s\n' % (args.nonce,args.program,name,page,encoded)).encode('ascii'))
    write_all(1,('LCEND1 %s %s\n'%(args.nonce,args.program)).encode('ascii'))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    p.add_argument('--manifest',type=Path,default=Path('/etc/paos/local-clis.json'))
    p.add_argument('--binding',type=Path,default=Path('/run/paos-driver-binding'))
    p.add_argument('--evidence',type=Path,required=True)
    p.add_argument('--seconds',type=int,default=120)
    p.add_argument('--output-limit',type=int,default=8 << 20)
    p.add_argument('--readout',action='store_true')
    p.add_argument('--nonce')
    p.add_argument('--effect-nonce')
    p.add_argument('--credentials-missing-nonce')
    p.add_argument('--multiline-nonce')
    p.add_argument('--keyboard-nonce')
    p.add_argument('program',choices=('claude','codex'))
    args = p.parse_args()
    try: return readout(args) if args.readout else run(args)
    except (OSError,ValueError): return 125


if __name__ == '__main__':
    raise SystemExit(main())
