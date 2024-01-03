import os
import time
import logging
from pathlib import Path

from .constants import LOGGER_NAME, EXLUSION_RULES
from . import syscalls
from .utils import run_with_output
from .machine import machine
from .mdatp import mdatp

log = logging.getLogger(LOGGER_NAME)

def reset_dispatch():
    auditd_pid = int(run_with_output("pgrep -f /sbin/auditd"))
    log.info(f"[>] auditd found with pid={auditd_pid}")
    run_with_output(f"kill -HUP {auditd_pid}")

def override_prompt(args):
    if os.path.exists(EXLUSION_RULES) and not args.override:
        override = input("The exclusion rule file already exist. Do you want to override it with new rules? [y/N] ").lower()
        if override =='y':
            args.override=True

def validate_exclusion_path(path):
    if not os.path.exists(path):
        log.warn(f'The path [{path}] doesn\'t exist and will not be added to the exlusion rules.')
        return False
    return True

def validate_pid(pid):
    if not os.path.exists(f'/proc/{pid}'):
        log.warn(f'The pid [{pid}] doesn\'t correspond to any running process. Will not be added to exlusion rules')
        return None

    pid_info = run_with_output(f'ps -o cmd --pid {pid}').split('\n')

    if len(pid_info) == 1: #process got killed
        return None
    return pid_info[1]

def create_exclusion_file(args):
    if args.arch and (args.arch == "32" or args.arch == "64"):
        ARCHITECTURE=f"b{args.arch}"
    else:
        ARCHITECTURE="b64"

    override_prompt(args)
    exclusions = ""
    syscall = syscalls.Syscalls64 if ARCHITECTURE == "b64" else syscalls.Syscalls32
    if args.exe:
        for e in args.exe:
            if not validate_exclusion_path(e):
                continue
            log.info(f"[>] setting an exe exclusion rule for {e}")
            exclusions += f"-a exit,never -F arch={ARCHITECTURE} -S {syscall.SOCKET} -S {syscall.CONNECT} -S {syscall.BIND} -S {syscall.ACCEPT} -S {syscall.ACCEPT4} -S {syscall.SETSOCKOPT} -F exe={e} -k exclude\n"
            exclusions += f"-a exit,never -F arch={ARCHITECTURE} -S {syscall.RENAME} -S {syscall.RENAMEAT} -S {syscall.RENAMEAT2} -S {syscall.RMDIR} -S {syscall.UNLINK} -S {syscall.UNLINKAT} -S {syscall.PTRACE} -F exe={e} -k exclude\n"
            exclusions += f"-a exit,never -F arch={ARCHITECTURE} -S {syscall.CHOWN} -S {syscall.FCHOWN} -S {syscall.FCHOWNAT} -S {syscall.CHMOD} -S {syscall.FCHMODAT} -S {syscall.FCHMOD} -S {syscall.BPF} -F exe={e} -k exclude\n"

    if args.pid:
        for p in args.pid:
            process = validate_pid(p)
            if not process:
                continue
            log.info(f"[>] setting a pid exclusion rule for pid {p} corresponding to process [{process}]")
            exclusions += f"-a exit,never -F arch={ARCHITECTURE} -S {syscall.SOCKET} -S {syscall.CONNECT} -S {syscall.BIND} -S {syscall.ACCEPT} -S {syscall.ACCEPT4} -S {syscall.SETSOCKOPT} -F pid={p} -k exclude\n"
            exclusions += f"-a exit,never -F arch={ARCHITECTURE} -S {syscall.RENAME} -S {syscall.RENAMEAT} -S {syscall.RENAMEAT2} -S {syscall.RMDIR} -S {syscall.UNLINK} -S {syscall.UNLINKAT} -S {syscall.PTRACE} -F pid={p} -k exclude\n"
            exclusions += f"-a exit,never -F arch={ARCHITECTURE} -S {syscall.CHOWN} -S {syscall.FCHOWN} -S {syscall.FCHOWNAT} -S {syscall.CHMOD} -S {syscall.FCHMODAT} -S {syscall.FCHMOD} -S {syscall.BPF} -F pid={p} -k exclude\n"

    if args.dir:
        for d in args.dir:
            if not validate_exclusion_path(d):
                continue
            log.info(f"[>] setting a path exclusion rule for path {d}")
            exclusions += f"-a exit,never -F arch={ARCHITECTURE} -S {syscall.RENAME} -S {syscall.RENAMEAT} -S {syscall.RENAMEAT2} -S {syscall.RMDIR} -S {syscall.UNLINK} -S {syscall.UNLINKAT} -S {syscall.PTRACE} -F dir={d} -k exclude\n"
            exclusions += f"-a exit,never -F arch={ARCHITECTURE} -S {syscall.CHOWN} -S {syscall.FCHOWN} -S {syscall.FCHOWNAT} -S {syscall.CHMOD} -S {syscall.FCHMODAT} -S {syscall.FCHMOD} -S {syscall.BPF} -F dir={d} -k exclude\n"

    if args.exe_dir:
        for ed in args.exe_dir:
            if not validate_exclusion_path(ed[0]) or not validate_exclusion_path(ed[1]):
                continue
            log.info(f"[>] setting a exe and path exclusion rule for exe {ed[0]} and path {ed[1]}")
            exclusions += f"-a exit,never -F arch={ARCHITECTURE} -S {syscall.RENAME} -S {syscall.RENAMEAT} -S {syscall.RENAMEAT2} -S {syscall.RMDIR} -S {syscall.UNLINK} -S {syscall.UNLINKAT} -S {syscall.PTRACE} -F exe={ed[0]} -F dir={ed[1]} -k exclude\n"
            exclusions += f"-a exit,never -F arch={ARCHITECTURE} -S {syscall.CHOWN} -S {syscall.FCHOWN} -S {syscall.FCHOWNAT} -S {syscall.CHMOD} -S {syscall.FCHMODAT} -S {syscall.FCHMOD} -S {syscall.BPF} -F exe={ed[0]} -F dir={ed[1]} -k exclude\n"


    if args.syscall:
        log.info(f"[>] Setting a syscall exclusion rule for {args.syscall}")
        rule = ' '.join(f"-S {s}" for s in args.syscall)
        exclusions += f"-a exit,never -F arch={ARCHITECTURE} {rule} -k exclude\n"

    if exclusions:
        if args.override: # remove previous exclusion files
            exclusions = "-D -k exclude\n" + exclusions
        log.info('Adding the following rules:\n{0}\n{1}\n{0}'.format('*'*10, exclusions))
        with Path(EXLUSION_RULES).open('w' if args.override else 'a') as rules_fp:
            rules_fp.write(exclusions)
            mdatp.restart_auditd()

def remove_exclusion_file():
    file = EXLUSION_RULES
    if os.path.exists(file):
        log.info(f"[>] removing {file}")
        os.remove(file)
        mdatp.restart_auditd()
    else:
        log.error(f'--remove flag was chosen but {file} does not exist')

def set_auditd_qdepth(q_depth):
    config_file = '/etc/audit/auditd.conf'
    if os.path.exists('/sbin/audispd'):
        if os.path.exists('/etc/audisp'):
            config_file = '/etc/audisp/audispd.conf'
        else:
            log.warn(f'[>] audispd exists but /etc/audisp doesn\'t exist. Using [{config_file}]')

    with Path(config_file).open() as f:
        q_lines = [l.strip() for l in f if "q_depth" in l]

    if q_lines:
        # update q_depth:
        run_with_output(f"sudo sed -i s/q_depth = .*/q_depth = {q_depth}/g {config_file}")
        log.info(f"[>] q_depth updated to {q_depth}")
    else:
        # set q_depth:
        with open(config_file, "a") as f:
            f.write(f"q_depth = {q_depth}\n")
            log.info(f"[>] q_depth not defined, added q_depth = {q_depth}")
    
    reset_dispatch()

def exclude(args):
    if args.list:
        log.info(run_with_output("auditctl -l"))

    if args.stat:
        log.info(run_with_output("aureport -x --summary"))
    
    if args.exe or args.pid or args.dir or args.exe_dir or args.syscall:
        create_exclusion_file(args)
    
    if args.remove:
        remove_exclusion_file()

    if args.queue:
        set_auditd_qdepth(args.queue)
