"""Dedicated F11 guest init: independent boot admission, mount, serve, drain.

The native owner authors FSG1 only after acquiring the exact partition lease.
No FSC1 request can create a Grant. This code never authorizes native storage,
claims stopped-domain proof or releases a native lease.
"""
from dataclasses import dataclass
import fcntl
import json
import math
import os
import re
import stat
import struct
import subprocess
import sys
import termios
import time
import tty

DEVICE = '/dev/vda'
MOUNT = '/mnt/paos-fs'
JOURNAL = '.paos-fsc1-journal'
BLKGETSIZE64 = 0x80081272
BLKFLSBUF = 0x1261


class Refused(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Refused(reason)


@dataclass(frozen=True)
class Admission:
    request: str
    job: str
    principal: str
    attachment: str
    generation: int
    maximum_bytes: int
    expires: float
    serial: int
    source: str
    destination: str
    boot_nonce: str
    partition_bytes: int


def name(value):
    return (re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', value) is not None
            and not value.endswith('.'))


def admission(cmdline, *, started):
    """FSG1 is native-authored boot metadata, never a copy request payload."""
    need(type(started) in (int, float) and math.isfinite(started), 'start')
    need(type(cmdline) is str and len(cmdline) <= 4096, 'cmdline')
    values = [v[len('paos.fsg1='):] for v in cmdline.split()
              if v.startswith('paos.fsg1=')]
    need(len(values) == 1 and re.fullmatch('[0-9a-f]{640}', values[0]), 'metadata')
    raw = bytes.fromhex(values[0])
    need(struct.unpack_from('<4sHH', raw) == (b'FSG1', 1, 1), 'version_backend')
    generation, maximum = struct.unpack_from('<QQ', raw, 72)
    lifetime, slen, dlen = struct.unpack_from('<IHH', raw, 88)
    serial, = struct.unpack_from('<Q', raw, 96)
    size, = struct.unpack_from('<Q', raw, 280)
    need(generation > 0 and 0 < maximum <= 1024**3 and
         0 < lifetime <= 300000 and serial > 0 and
         size >= 512 and size % 512 == 0, 'bounds')
    need(1 <= slen <= 80 and 1 <= dlen <= 80 and
         not any(raw[104+slen:184] + raw[184+dlen:264] + raw[288:]), 'padding')
    try:
        source = raw[104:104+slen].decode('ascii')
        destination = raw[184:184+dlen].decode('ascii')
    except UnicodeError as exc:
        raise Refused('name') from exc
    need(name(source) and name(destination) and source != destination, 'name')
    tokens = [raw[n:n+16] for n in (8, 24, 40, 56, 264)]
    need(all(any(v) for v in tokens), 'identity')
    return Admission(*(v.hex() for v in tokens[:4]), generation, maximum,
                     started+lifetime/1000, serial, source, destination,
                     tokens[4].hex(), size)


def mounts(text):
    """Fixed names have no mountinfo escapes; reject aliases by device number."""
    result = []
    for line in text.splitlines():
        fields = line.split()
        need(len(fields) >= 10 and '-' in fields, 'mountinfo')
        divider = fields.index('-')
        need(divider >= 6 and len(fields) >= divider+4, 'mountinfo')
        result.append(dict(device=fields[2], point=fields[4], options=fields[5],
                           backend=fields[divider+1], source=fields[divider+2],
                           super_options=fields[divider+3]))
    return result


def mount_table():
    with open('/proc/self/mountinfo', encoding='ascii') as stream:
        return mounts(stream.read())


def validate_vbr(raw, expected_serial):
    need(len(raw) == 512 and raw[3:11] == b'NTFS    ' and
         raw[510:] == b'\x55\xaa' and
         struct.unpack_from('<Q', raw, 72)[0] == expected_serial, 'ntfs_identity')


def run(argv, expires):
    remaining = expires-time.monotonic()
    need(remaining > 0, 'expired')
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=min(10, remaining), check=False,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    need(result.returncode == 0, 'guest_command')
    return result.stdout.decode('ascii', 'strict')


def open_journal(root):
    try:
        os.mkdir(JOURNAL, 0o700, dir_fd=root)
        os.fsync(root)
    except FileExistsError:
        pass
    fd = os.open(JOURNAL, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
    try:
        st, base = os.fstat(fd), os.fstat(root)
        need(st.st_dev == base.st_dev and st.st_uid == os.geteuid() and
             stat.S_IMODE(st.st_mode) == 0o700, 'journal_identity')
        return fd
    except BaseException:
        os.close(fd)
        raise


class Mount:
    def __init__(self, grant):
        self.grant = grant
        self.fd = None
        self.mounted = False
        self.root = self.journal = None

    def attach(self):
        self.fd = os.open(DEVICE, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        st = os.fstat(self.fd)
        need(stat.S_ISBLK(st.st_mode), 'block_device')
        dev = f'{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}'
        with open('/sys/block/vda/dev', encoding='ascii') as stream:
            need(stream.read().strip() == dev, 'block_identity')
        with open('/sys/block/vda/ro', encoding='ascii') as stream:
            need(stream.read().strip() == '0', 'block_readonly')
        need(struct.unpack('<Q', fcntl.ioctl(self.fd, BLKGETSIZE64, b'\0'*8))[0]
             == self.grant.partition_bytes, 'partition_size')
        validate_vbr(os.pread(self.fd, 512, 0), self.grant.serial)
        need(not any(m['device'] == dev or m['point'] == MOUNT or
                     m['source'] == DEVICE for m in mount_table()), 'mounted_alias')
        run(['/usr/bin/ntfs-3g.probe', '--readwrite', DEVICE], self.grant.expires)
        info = run(['/usr/bin/ntfsinfo', '-m', DEVICE], self.grant.expires)
        flags = re.findall(r'^\s*Volume Flags:\s*(0x[0-9a-fA-F]+)\s*$', info, re.M)
        need(len(flags) == 1 and int(flags[0], 16) in (0, 0x80), 'ntfs_flags')
        os.makedirs(MOUNT, mode=0o700, exist_ok=True)
        need(stat.S_ISDIR(os.lstat(MOUNT).st_mode) and not os.listdir(MOUNT), 'mountpoint')
        # No force/recover/remove_hiberfile and no historical device/label grant.
        # Mark uncertain before invoking FUSE: timeout may leave a live mount.
        self.mounted = True
        run(['/usr/bin/ntfs-3g', '-o', 'rw,permissions,nosuid,nodev,noexec', DEVICE, MOUNT],
            self.grant.expires)
        observed = [m for m in mount_table() if m['point'] == MOUNT]
        need(len(observed) == 1 and observed[0]['source'] == DEVICE and
             observed[0]['backend'] == 'fuseblk' and
             'rw' in observed[0]['options'].split(',') and
             'rw' in observed[0]['super_options'].split(','), 'mount_binding')
        self.root = os.open(MOUNT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.journal = open_journal(self.root)

    def detach(self):
        # Never hide uncertain teardown or emit a native reclaim receipt.
        result = dict(linux_unmounted=False, linux_block_flush=False)
        for key in ('journal', 'root'):
            fd = getattr(self, key)
            if fd is not None:
                os.close(fd)
                setattr(self, key, None)
        try:
            if self.mounted:
                # Separate finite cleanup allowance, not new workload authority.
                end = time.monotonic()+10
                run(['/bin/busybox', 'umount', MOUNT], end)
                need(not any(m['point'] == MOUNT or m['source'] == DEVICE
                             for m in mount_table()), 'unmount_unobserved')
                self.mounted = False
                result['linux_unmounted'] = True
                # No flush on pre-mount admission refusal (e.g. an alias).
                os.fsync(self.fd)
                fcntl.ioctl(self.fd, BLKFLSBUF)
                result['linux_block_flush'] = True
            return result
        finally:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None


class Finalizer:
    """One actual detach attempt shared by wire FINISH and abnormal cleanup."""
    def __init__(self, mount, receipt):
        self.mount = mount
        self.receipt = receipt
        self.attempted = False

    def __call__(self):
        need(not self.attempted, 'finalize_repeated')
        self.attempted = True
        try:
            result = self.mount.detach()
            self.receipt.update(result)
            return result
        except (OSError, ValueError, subprocess.SubprocessError):
            self.receipt['error'] = 'guest_teardown_uncertain'
            raise


def main():
    mount = channel = finalizer = None
    receipt = dict(schema='paos.fsg1.guest-terminal.v1', service_return=None,
                   linux_unmounted=False, linux_block_flush=False,
                   native_physical_flush=False, native_reclaimed=False)
    try:
        started = time.monotonic()
        need(os.geteuid() == 0, 'guest_root')
        with open('/proc/cmdline', encoding='ascii') as stream:
            grant = admission(stream.read(4097), started=started)
        # Package owns this immutable module directory. -I -S disables ambient
        # PYTHONPATH/site, so loading workers requires this explicit fixed path.
        sys.path.insert(0, '/opt/paos/fs')
        from guest_filesystem_copy import Grant
        from guest_filesystem_copy_wire import serve
        receipt.update(attachment=grant.attachment, generation=grant.generation,
                       boot_nonce=grant.boot_nonce, job=grant.job)
        mount = Mount(grant)
        finalizer = Finalizer(mount, receipt)
        mount.attach()
        root = os.fstat(mount.root)
        admitted = Grant(root_fd=mount.root, journal_fd=mount.journal,
            root_dev=root.st_dev, root_ino=root.st_ino, principal=grant.principal,
            attachment=grant.attachment, generation=grant.generation,
            request=grant.request, job=grant.job, source=grant.source,
            destination=grant.destination, backend='ntfs',
            maximum_bytes=grant.maximum_bytes, expires=grant.expires)
        need(time.monotonic() < grant.expires, 'expired')
        channel = os.open('/dev/hvc1', os.O_RDWR | os.O_NOCTTY |
                          os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(stat.S_ISCHR(os.fstat(channel).st_mode), 'channel')
        tty.setraw(channel, termios.TCSANOW)
        receipt['service_return'] = serve(channel, admitted, finalize=finalizer)
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeError):
        receipt['error'] = 'guest_setup_or_service'
    finally:
        if channel is not None:
            os.close(channel)
        if finalizer is not None and not finalizer.attempted:
            try:
                finalizer()
            except (OSError, ValueError, subprocess.SubprocessError):
                receipt['error'] = 'guest_teardown_uncertain'
        print(json.dumps(receipt, sort_keys=True), flush=True)
    return int('error' in receipt or receipt['service_return'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
