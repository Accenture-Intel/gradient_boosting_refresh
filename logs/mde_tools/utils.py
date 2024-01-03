from collections import defaultdict
import io
import re
import os
import platform
from subprocess import check_output, Popen, STDOUT, CalledProcessError, call
import time
import shlex
import logging
import datetime
import zipfile
import functools
import sh
import shutil
import tempfile
from . import constants

log = logging.getLogger(constants.LOGGER_NAME)

CONNECTIVITY_LINE_REGEX = re.compile(r'^Testing connection with (.+) \.\.\. \[(.+)\]$')
MDATP_KEY = re.compile("-F key=mdatp")

SUPPORTED_GEOS = ["EUS", "CUS", "UKS", "WEU", "NEU"]

CONFLICTING_AGENTS =   {
                        "mcafee": { "masvc", "macmnsvc", "cmdagent","macompatsvc", "MFEcma" },
                        "carbon black": {" cbagentd", "cbdaemon", "cbosxsensorservice", "cbsensor" },
                        "symantec": { "rtvscand" },
                        "sophos": { "savconfig", "savdctl", "savdstatus", "savlog", "savscan", "savsetup", "savupdate", "savscand" },
                        "panda": { "pcop" },
                        "trendmicro" : { "ds_agent" },
                        "crowdstrike" : { "falcon-sensor" }
                        }

CONFLICTING_BINARIES = { "/usr/bin/adclient": "adclient", "/usr/local/sbin/haproxy": "haproxy" }

DEBUG_MODE = 'DEBUG' in os.environ.keys() and os.environ['DEBUG'] in [1, "1", "True", "true", True]

SKIP_KNOWN_ISSUES = 'SKIP_KNOWN_ISSUES' in os.environ.keys() and os.environ['SKIP_KNOWN_ISSUES'] in [1, "1", "True", "true", True]

# -- Paths ----
ONBOARDING_PACKAGE = 'WindowsDefenderATPOnboardingPackage'
OFFBOARDING_PACKAGE = 'WindowsDefenderATPOffboardingPackage_valid_until'

DIY_PACKAGE_MACOS = 'MDATP MacOS DIY.zip'
DIY_PACKAGE_LINUX = 'MDE Linux DIY.zip'
LINUX_DIY_SCRIPT = 'mde_linux_edr_diy.sh'

ONBOARDING_SCRIPTS = ['WindowsDefenderATPOnboarding.py',                # legacy name
                      'MicrosoftDefenderATPOnboardingMacOs.py',         # macOS
                      'MicrosoftDefenderATPOnboardingLinuxServer.py']   # Linux

COLLECTION_DIR = 'mdatp'
APP_COMPAT_JSON = 'results_for_pytest.json'

# -- Strings
GLOBAL_CAPPING_MSG = "Global capping status changed, patternSequence:{pattern_sequence}, isLimitReached:{limit_reached}"

# -- URLs ----
DIY_URL_MACOS  = "https://aka.ms/mdatpmacosdiy"
DIY_URL_LINUX  = "https://aka.ms/linuxdiy"
EICAR_TEST_URL = "https://www.eicar.org/download/eicar.com.txt"

def collect_command_output_to_file(prefix, filename, command, new_env):
    output = io.StringIO()
    try:
        cmd = sh.Command(command)
        cmd(_out=output, _env=new_env)
    except:
        output.write("Could not run command" + command)

    _, file_path = tempfile.mkstemp(prefix=f'{prefix}_{get_time_string()}', suffix='.txt')
    with open(file_path, 'w') as writer:
        writer.write(output.getvalue())
    return {filename: file_path}


def modify_ld_path():
    env = dict(os.environ)
    if constants.IS_COMPILED_AS_BINARY and platform.system() == 'Linux':
        lp_key = 'LD_LIBRARY_PATH'
        lp_orig = env.get(lp_key + '_ORIG')

        if lp_orig is not None:
            env[lp_key] = lp_orig
        else:
            env.pop(lp_key, None)

    return env

def run(cmd, verbose = True):
    log.debug(f'running [{cmd}]')
    return 0 == call(cmd, shell=True, env=modify_ld_path())

# check_output does not support pipe out of the box
MAX_OUTPUT_LEN = 256
def run_with_output(cmd: str, timeout_in_sec: int = 5, return_stdout_on_err=False, verbose=True):
    log.debug(f'running_with_output [{cmd}]')
    try:
        bytes_output = check_output(shlex.split(cmd), stderr=STDOUT, timeout=timeout_in_sec, env=modify_ld_path())
        output = bytes_output.decode('utf8', 'ignore').strip()
        log.debug(f"output [{output[:MAX_OUTPUT_LEN]}{'...' if len(output)>MAX_OUTPUT_LEN else ''}]")
        return output
    # Incase the exit code of the called process is non zero
    except CalledProcessError as non_zero_error:
        output = non_zero_error.output.decode('utf8', 'ignore').strip() if non_zero_error.output else ""
        stderr = non_zero_error.stderr.decode('utf8', 'ignore').strip() if non_zero_error.stderr else ""
        if verbose:
            log.warning(f"Executing failed with return code: {non_zero_error.returncode}")
            log.warning(f"output [{output[:MAX_OUTPUT_LEN]}{'...' if len(output)>MAX_OUTPUT_LEN else ''}]")
            log.warning(f"stderr [{stderr[:MAX_OUTPUT_LEN]}{'...' if len(stderr)>MAX_OUTPUT_LEN else ''}]")
        return output if return_stdout_on_err else None
    except Exception as e:
        log.error(f'run failed {e}')
        return None

def run_and_get_pid(cmd):
    proc = Popen(cmd.split(' '), env=modify_ld_path())
    proc.terminate()
    return proc.pid

def convert_to_timestamp(time_str):
    return time.mktime(time.strptime(time_str.split('.')[0], '%Y-%m-%dT%H:%M:%S'))

def wait(time_sec, reason, verbose=True):
    if verbose:
        log.info(f"[SLEEP] [{time_sec}sec] " + reason)
    time.sleep(time_sec)

def trace(msg):
    log.debug(msg)

def error(msg):
    log.error(msg)
    return False

def print_title_and_measure_time(f):
    print(f"decorating {f.__name__}")
    def wrapper(*args):
        log.info(f"-- {f.__name__} START --")
        start_time = time.time()
        try:
            f(*args)
            elapsed_time = time.time() - start_time
            log.info(f"-- {f.__name__} PASSED [{elapsed_time:.2f}sec] --")
        except Exception as e:
            elapsed_time = time.time() - start_time
            log.error(f"-- {f.__name__} FAILED [{elapsed_time:.2f}sec] --")
            log.info("top cpu consumers:\n" + top_cpu_consumers())
            raise e
    wrapper.__name__ = f.__name__
    return wrapper

def skip_known_issues():
    return SKIP_KNOWN_ISSUES

def parse_connectivity_test(connectivity_result: str):
    results = defaultdict(list)
    for line in connectivity_result.split('\n'):
        regex_extraction = CONNECTIVITY_LINE_REGEX.findall(line)
        if regex_extraction:
            host, status = regex_extraction[0]
            status = status == 'OK'
            # EDR C&C
            if 'winatp' in host:
                results['edr_cnc'].append(status)
            # EDR Cyber
            elif 'events' in host:
                results['edr_cyber'].append(status)
            # AV
            else:
                results['av'].append(status)
    return results

def retrieve_event_id_for_connectivity_results(status_array, good_id, warn_id, error_id):
    os_prefix = '2' if platform.system() == 'Darwin' else '3'
    if all(status_array):
        return f'{os_prefix}{good_id}'
    elif any(status_array):
        return f'{os_prefix}{warn_id}'
    else:
        return f'{os_prefix}{error_id}'

def retrieve_event_id_for_processes(status_array, good_id, error_id):
    os_prefix = '2' if platform.system() == 'Darwin' else '3'
    if all(status_array):
        return f'{os_prefix}{good_id}'
    else:
        return f'{os_prefix}{error_id}'

# This functions receives process counter and returns string represting this process status
def translate_process_counter_to_string(process_count):
    if process_count == 0:
        return 'Down'
    elif process_count == 1:
        return 'Running'
    else:
        return 'Error'

def top_cpu_consumers(n=5):
    return Popen(f"ps axo pid,pcpu,pmem,comm | sort -nrk 2,3 | head -n{n}", env=modify_ld_path()).read()

def is_process_running(process_name):
    return run_with_output(f"sh -c 'ps aux | grep {process_name} | grep -v grep'", verbose=False)

def collect_mde_conflicts():
    conflicting_agents = []
    conflicting_orgs = set()
    for org, agents in CONFLICTING_AGENTS.items():
        for agent in agents:
            conflicting_agent_data = is_process_running(agent)
            if conflicting_agent_data is not None:
                conflicting_agents.append(f"{org} - {agent}:\n{conflicting_agent_data}")
                conflicting_orgs.add(org)
    if len(conflicting_agents) > 0:
        conflicting_agents_string = 'conflicting security tools'
        conflicting_agents = '\n'.join([conflicting_agents_string, '=' * len(conflicting_agents_string) , '\n\n'.join(conflicting_agents)])
    return conflicting_agents, conflicting_orgs

def confilicting_orgs():
    try:
        _, conflicting_orgs = collect_mde_conflicts()
        return ", ".join(org for org in conflicting_orgs)
    except Exception as e:
        log.exception(f"Conflicting_orgs raised an exception {e}")
        return []

def collect_conflicting_binaries(audit_rules):
    conflicting_binaries = set()
    for binary in CONFLICTING_BINARIES.keys():
        if os.path.exists(binary):
            conflicting_binaries.add(binary)
    return ', '.join(binary for binary in conflicting_binaries if not is_process_excluded(CONFLICTING_BINARIES[binary], audit_rules))

def is_process_excluded(process, audit_rules): 
    exclusion_rules_by_name =  f"-a (?:exit,never|never,exit).* -F exe={process}"
    process_pid_list = str(run_with_output(f"pgrep {process}")).splitlines()
    return re.search(exclusion_rules_by_name, audit_rules) or all(re.search(r'-a (?:exit,never|never,exit).* -F pid=' + pid, audit_rules) for pid in process_pid_list)

def collect_dlp_enforcement_policy():
    dlp_enforcement_policy = run_with_output(f"sudo " + constants.DLP_DIAGNOSTIC_FILE_PATH + " --policy-info", timeout_in_sec=20)
    if dlp_enforcement_policy is None:
        log.warn("Unable to collect policy")
        return
    return dlp_enforcement_policy
   
def collect_dlp_classification_policy():
    dlp_classification_policy = run_with_output(f"sudo "+ constants.DLP_DIAGNOSTIC_FILE_PATH +" --classification-info", timeout_in_sec=20)
    if dlp_classification_policy is None:
        log.warn("Unable to collect policy")
        return
    return dlp_classification_policy

def collect_extended_attribute_info(args):
    target_file_name = args.target_file
    extended_attribute_info = run_with_output(f"sudo "+ constants.EXTENDED_ATTR_FILE_PATH +" " + target_file_name, timeout_in_sec=20)
    if extended_attribute_info is None:
        log.warn("empty output")
        return
    return extended_attribute_info

def collect_running_conflicting_binaries(audit_rules):
    conflicting_binaries = collect_conflicting_binaries(audit_rules)
    if len(conflicting_binaries) > 0:
        conflicting_binaries_string = 'conflicting binaries'
        conflicting_binaries = '\n'.join([conflicting_binaries_string, '=' * len(conflicting_binaries_string), conflicting_binaries])
    return conflicting_binaries

def collect_non_mdatp_auditd_rules(auditd_rules):
    rules_list = auditd_rules.splitlines()[2:]
    output_rules = '\n'.join(e for e in rules_list if not MDATP_KEY.search(e))
    if len(output_rules) > 0:
        non_mdatp_rules_string = 'non-mdatp rules'
        non_mdatp_rules = '\n'.join([non_mdatp_rules_string, '=' * len(non_mdatp_rules_string), output_rules])
    else:
        non_mdatp_rules = ""
    return non_mdatp_rules

def get_time_string(time = datetime.datetime.utcnow()):
    return time.strftime("%Y_%m_%d_%H_%M_%S")

def wrap_function_log_exception(func):
    try:
        return func()
    except Exception as e:
        log.error(f'Function failed: {e}')
        return e

def create_zip(zip_file, *, path=None, files=None, zipdir='', prefix_pattern='', suffix_pattern='', retain_dir_tree=False, recursive=False, predicate=None, mode='w'):
    if path is None and files is None:
        raise RuntimeError('Pass either path or files list')

    if path:
        def filter_predicate(f):
            return f.startswith(prefix_pattern) and f.endswith(suffix_pattern)

        def reduce_routine(paths):
            for path in paths:
                all_files = os.walk(path, topdown=True)
                if not recursive:
                    all_files = [next(all_files)]

                for root, _, files in all_files:
                    for f in files:
                        if filter_predicate(f) and (predicate is None or predicate(os.path.join(root, f))):
                            yield os.path.join(root, f)

        if not isinstance(path, list):
            path = [path]

        files = reduce_routine(path)

    with zipfile.ZipFile(zip_file, mode, zipfile.ZIP_DEFLATED) as zipfile_handle:
        unzipped_files = []
        zipped_file_count = 0 
        for f in files:
            try:
                if retain_dir_tree:
                    zipfile_handle.write(f, os.path.join(zipdir, f.lstrip('/')))
                else:
                    zipfile_handle.write(f, os.path.join(zipdir, os.path.basename(f)))
                zipped_file_count += 1
            except Exception as e:
                unzipped_files.append(f)
                continue
        
        max_error_output_files = 5
        total_unzipped_files_count = len(unzipped_files)
        unzipped_files = unzipped_files[:min(total_unzipped_files_count,max_error_output_files)]
        if len(unzipped_files) > 0:
            log.info(f"Unable to zip {total_unzipped_files_count} out of total {zipped_file_count + total_unzipped_files_count} files.") 
            log.info(f"Unzipped files : {unzipped_files}. Output truncated to {max_error_output_files} files.")

    return True

def command_exists(command_name):
    return shutil.which(command_name) is not None