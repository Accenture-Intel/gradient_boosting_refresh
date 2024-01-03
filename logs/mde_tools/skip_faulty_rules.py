import logging, os
from .mdatp import mdatp
from pathlib import Path
from .utils import run_with_output

from .constants import LOGGER_NAME, SKIP_FAULTY_RULES

log = logging.getLogger(LOGGER_NAME)

def set_skip_faulty_rule():
    skip_faulty_rule = f'\n'
    skip_faulty_rule += f'## Auditd rules for continuing through faulty rules by MDATP\n'
    skip_faulty_rule += f'## This file is managed by MDATP. Please do not edit the file\n'
    skip_faulty_rule += f"## cdbb87e7-66d1-40e8-b090-30ff3e88fc08\n"
    skip_faulty_rule += f"-c\n"

    with Path(SKIP_FAULTY_RULES).open('w') as rules_fp:
        rules_fp.write(skip_faulty_rule)

def disable_skip_faulty_rule():
    if os.path.exists(SKIP_FAULTY_RULES):
        os.remove(SKIP_FAULTY_RULES)

def skip_faulty_rules(args):
    log.warning(f"[!] Enabling the continous loading rules in spite of an error.")
    if args.enable == 'false':
        log.info(f"[>] Disabling skip faulty rules")
        disable_skip_faulty_rule()
    elif args.enable == 'true':
        log.info(f"[>] Enabling skip faulty rules")
        set_skip_faulty_rule()
    
    assert mdatp.restart_auditd(), "Failed to restart auditd"

        