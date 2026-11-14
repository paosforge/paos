#!/usr/bin/python3
"""Passive, previously trusted UserPromptSubmit callback. Never runs a CLI.

Only a fixed public comparison and original process identities leave memory.
No hook installation, config/trust changes, transcript reads or provider actions.
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import stat
import time

ENV = 'PAOS_CLI_PROMPT_CONTEXT'
CONTEXT = 'prompt-context.json'
RECEIPT = 'prompt-receipt.json'
DUPLICATE = 'prompt-duplicate'
SCHEMA = 'paos.cli-prompt-receipt.v1'
FIELDS = {'schema','status','nonce','process','binding','guest_boot_id','prepared_ns','deadline_ns'}


def need(ok):
    if not ok:raise ValueError('refused')


def native():
    # Reuse the original launcher custody/binding/executable readers, not a
    # second interpretation of the native START binding or executable pin.
    p=Path(__file__).with_name('paos-local-cli')
    if not p.exists():p=Path(__file__).with_name('launch.py')  # source layout
    loader=importlib.machinery.SourceFileLoader('paos_cli_original',str(p))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    m=importlib.util.module_from_spec(spec);loader.exec_module(m)
    return m


def expected(program,nonce):
    need(program in ('claude','codex') and type(nonce) is str and
         re.fullmatch('[0-9a-f]{16}',nonce) and nonce!='0'*16)
    return 'Read this two-line request.\nReply with paos-multiline '+program+' '+nonce


def encode(v):
    return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')


def pairs(items):
    d={}
    for k,v in items:need(k not in d);d[k]=v
    return d


def parse(data):
    def bad(_):raise ValueError('refused')
    return json.loads(data,object_pairs_hook=pairs,parse_constant=bad)


def store(directory,name,data):
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
    try:
        view=memoryview(data)
        while view:
            n=os.write(fd,view);need(n>0);view=view[n:]
        os.fsync(fd)
    finally:os.close(fd)


def read(directory,name,maximum=8192):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and
             stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and 0<before.st_size<=maximum)
        data=os.read(fd,maximum+1);after=os.fstat(fd)
        need(len(data)==before.st_size and
             (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns))
        return data
    finally:os.close(fd)


def prepare(directory,program,nonce,process,executable,binding,binding_path,boot_id,deadline_ns):
    expected(program,nonce)
    m=native()
    value=dict(schema='paos.cli-prompt-context.v1',program=program,nonce=nonce,
        process=process,executable=executable,binding=binding,binding_path=str(binding_path),
        guest_boot_id=boot_id,launcher=dict(pid=os.getpid(),start_ticks=m.start_ticks(os.getpid())),
        prepared_ns=time.monotonic_ns(),deadline_ns=deadline_ns)
    store(directory,CONTEXT,encode(value))
    return value


def process(pid):
    raw=Path('/proc/%d/stat'%pid).read_bytes()
    need(len(raw)<=2048)
    words=raw.rsplit(b')',1)[1].split()
    need(words[0] not in (b'Z',b'X',b'x'))
    return dict(pid=pid,ppid=int(words[1]),start_ticks=int(words[19]))


def observe(c,m):
    need(type(c) is dict and set(c)=={'schema','program','nonce','process','executable','binding',
        'binding_path','guest_boot_id','launcher','prepared_ns','deadline_ns'} and c['schema']=='paos.cli-prompt-context.v1')
    expected(c['program'],c['nonce'])
    need(type(c['prepared_ns']) is int and type(c['deadline_ns']) is int and
         0<c['prepared_ns']<=time.monotonic_ns()<c['deadline_ns'])
    p=c['process'];need(type(p) is dict)
    for k in ('pid','start_ticks','exec_start_ticks','session','process_group'):
        need(type(p.get(k)) is int and p[k]>0)
    need(p['pid']==p['session']==p['process_group'] and p['start_ticks']==p['exec_start_ticks'])
    parent=c['launcher'];need(type(parent) is dict and set(parent)=={'pid','start_ticks'})
    need(all(type(v) is int and v>0 for v in parent.values()))
    need(process(parent['pid'])['start_ticks']==parent['start_ticks'])
    chain=[];current=os.getpid()
    for _ in range(8):
        step=process(current);chain.append(step)
        if current==p['pid']:break
        current=step['ppid']
    need(2<=len(chain)<=8 and chain[-1]==dict(pid=p['pid'],ppid=parent['pid'],start_ticks=p['start_ticks']))
    need(os.getsid(p['pid'])==p['session'] and os.getpgid(p['pid'])==p['process_group'])
    need(set(p)=={'pid','start_ticks','exec_start_ticks','session','process_group','executable'} and
         p['executable']==os.readlink('/proc/%d/exe'%p['pid']))
    actual=os.open('/proc/%d/exe'%p['pid'],os.O_RDONLY|os.O_CLOEXEC)
    try:need(m.executable_observation(actual)==c['executable'])
    finally:os.close(actual)
    need(m.read_binding(c['binding_path'])==c['binding'] and
         Path('/proc/sys/kernel/random/boot_id').read_text().strip()==c['guest_boot_id'])
    # Recheck births/edges after executable hashing and the binding read.
    need(all(process(v['pid'])==v for v in chain) and
         process(parent['pid'])['start_ticks']==parent['start_ticks'])
    return chain


def private_input():
    data=bytearray();end=time.monotonic()+1
    while True:
        left=end-time.monotonic();need(left>0 and select.select([0],[],[],left)[0])
        chunk=os.read(0,65537-len(data));data.extend(chunk)
        need(len(data)<=65536)
        if not chunk:return parse(data)


def callback():
    """Exit silently and successfully even on refusal; never block a prompt."""
    directory=-1
    try:
        path=Path(os.environ.get(ENV,''))
        need(path.is_absolute() and path.name==CONTEXT and '..' not in path.parts)
        directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        for part in path.parent.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            os.close(directory);directory=child
        ds=os.fstat(directory)
        need(ds.st_uid==os.getuid() and stat.S_IMODE(ds.st_mode)==0o700)
        c=parse(read(directory,CONTEXT));m=native()
        # This original process join is a prerequisite for recording anything.
        chain=observe(c,m)
        receipt={k:c[k] for k in FIELDS-{'schema','status'}}
        receipt.update(schema=SCHEMA,status='malformed',ancestry=chain,executable=c['executable'])
        try:
            v=private_input()
            need(type(v) is dict and v.get('hook_event_name')=='UserPromptSubmit' and type(v.get('prompt')) is str)
            receipt['status']='exact' if v['prompt']==expected(c['program'],c['nonce']) else 'mismatch'
        except (OSError,ValueError,TypeError,RecursionError):pass
        # Discard v/private bytes. Only these fixed facts can reach disk.
        receipt['ancestry']=observe(c,m);receipt['callback_ns']=time.monotonic_ns()
        try:store(directory,RECEIPT,encode(receipt))
        except FileExistsError:
            try:store(directory,DUPLICATE,b'duplicate\n')
            except FileExistsError:pass
    except (OSError,ValueError,TypeError,KeyError,IndexError,RecursionError):pass
    finally:
        if directory>=0:os.close(directory)
    return 0


def collect(directory,context):
    """Only after original descendant retirement; remove transient context."""
    receipt=dict(schema=SCHEMA,status='absent')
    try:
        try:receipt=parse(read(directory,RECEIPT))
        except FileNotFoundError:pass
        try:
            need(read(directory,DUPLICATE)==b'duplicate\n')
            receipt=dict(schema=SCHEMA,status='duplicate')
        except FileNotFoundError:pass
    except (OSError,ValueError,TypeError,RecursionError):receipt=dict(schema=SCHEMA,status='refused')
    # Never project foreign fields or strings into result.json, even if an
    # original child changed a local artifact. Saved reader checks all allowed
    # fields too; failed shape becomes a finite refusal rather than leaked bytes.
    try:
        need(type(receipt) is dict and receipt.get('schema')==SCHEMA)
        if receipt.get('status') in ('absent','refused','duplicate'):
            need(set(receipt)=={'schema','status'})
        else:
            need(receipt.get('status') in ('exact','mismatch','malformed') and
                 set(receipt)==FIELDS|{'callback_ns','ancestry','executable'})
            for k in FIELDS-{'schema','status'}:need(receipt[k]==context[k])
            need(receipt['executable']==context['executable'] and
                 type(receipt['callback_ns']) is int and context['prepared_ns']<=receipt['callback_ns']<context['deadline_ns'])
            chain=receipt['ancestry'];need(type(chain) is list and 2<=len(chain)<=8)
            for step in chain:
                need(type(step) is dict and set(step)=={'pid','ppid','start_ticks'} and
                     all(type(v) is int and v>0 for v in step.values()))
            need(len({v['pid'] for v in chain})==len(chain) and
                 all(a['ppid']==b['pid'] for a,b in zip(chain,chain[1:])) and
                 chain[-1]==dict(pid=context['process']['pid'],ppid=context['launcher']['pid'],start_ticks=context['process']['start_ticks']))
    except (ValueError,TypeError,KeyError):
        receipt=dict(schema=SCHEMA,status='refused')
    for name in (CONTEXT,):
        try:os.unlink(name,dir_fd=directory)
        except FileNotFoundError:pass
    return receipt


if __name__=='__main__':raise SystemExit(callback())
