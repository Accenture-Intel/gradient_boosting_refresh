import logging
from pathlib import Path
from .mdatp import mdatp
from .utils import run_with_output

from .constants import LOGGER_NAME, RATE_LIMIT_RULES

log = logging.getLogger(LOGGER_NAME)

def get_rate_limit():
    command = 'sudo auditctl -s'
    return run_with_output(command).split('\n')[3].split(' ')[-1]

def set_rate_limit(limit):
    rate_limit = f'\n'
    rate_limit += f'## Auditd rules for rate limiting by MDATP\n'
    rate_limit += f'## This file is managed by MDATP. Please do not edit the file\n'
    rate_limit += f"## cdbb87e7-66d1-40e8-b090-30ff3e88fc08\n"
    rate_limit += f"-r {limit}\n"

    with Path(RATE_LIMIT_RULES).open('w') as rules_fp:
        rules_fp.write(rate_limit)

def rate_limiter(args):
    log.warning(f"[!] Updating rate limit will update the limits for auditd events for all the applications using auditd. This may cause issues with other applications.")
    if args.enable:
        if args.enable == 'false':
            log.info(f"[>] Disabling rate limiting")
            limit = 0
        elif args.enable == 'true':
            log.info(f"[>] Enabling rate limiting, setting rate limit to 2500")
            limit = 2500
        else:
            log.info(f"[>] Wrong arguments passed. Please check help for more details.")
            return
    elif args.rate:
        log.info(f"[>] Setting rate limit to {args.rate}")
        limit = args.rate
    else:
        log.info(f"[>] Wrong arguments passed. Please check help for more details.")
        return    
    
    if str(limit) == get_rate_limit():
        log.info(f"[>] Rate limit already set to {limit}")
        return

    set_rate_limit(limit)
    assert mdatp.restart_auditd(), "Failed to restart auditd"

    rate_limit = get_rate_limit()

    if not str(limit) == rate_limit:
        if limit == 0:
            log.error(f"[!] Failed to disable rate limiting. Current rate limit is {rate_limit}")
        else:
            log.error(f"[!] Failed to set rate limit to {limit}. Current rate limit is {rate_limit}")
        os.remove(RATE_LIMIT_RULES)
    else:
        if limit == 0:
            log.info(f"[>] Rate limiting disabled")
        else:
            log.info(f"[>] Rate limit set to {limit}")
