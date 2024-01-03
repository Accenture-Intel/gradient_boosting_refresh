
import os
import stat
from .utils import run, run_with_output

def get_permission(path):
    return oct(os.stat(path)[stat.ST_MODE])[-3:]

def set_permission(path, permission):
    os.chmod(path, int(str(permission), 8))

def get_acl(path, type_, name):
    output = run_with_output(f"getfacl {path} --no-effective", timeout_in_sec=20)
    acl = output.split('\n')
    required = list(filter(lambda x: x.startswith(f'{type_}:{name}'), acl))
    return required[0].split(':')[-1] if required else ""

def set_acl(path, type_, name, permission):
    prefix = 'g:' if type_ == 'group' else ""
    run(f"setfacl -m {prefix}{name}:{permission} {path}")

