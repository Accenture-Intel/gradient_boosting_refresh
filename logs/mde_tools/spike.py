from .mdatp import mdatp
from .utils import run, run_with_output, get_time_string
from mde_tools import constants
from .diagnostic import collect_mde_diagnostic
from . import constants

import os
import time
import shutil
import logging
import datetime
import subprocess
import datetime

log = logging.getLogger(constants.LOGGER_NAME)

def get_pids():
    daemon_process = subprocess.Popen(['ps', '-ef'], stdout=subprocess.PIPE)
    daemon_output = subprocess.check_output(['grep', '/opt/microsoft/mdatp/sbin/wdavdaemon unprivileged'],
                                            stdin=daemon_process.stdout).decode()
    daemon_process.wait()
    daemon_pid = daemon_output.split()[2]
    engine_pid = int(subprocess.check_output(["pgrep", "-f", "/opt/microsoft/mdatp/sbin/wdavdaemon unprivileged"]).decode())
    edr_pid = int(subprocess.check_output(["pgrep", "-f", "/opt/microsoft/mdatp/sbin/wdavdaemon edr"]).decode())
    return (daemon_pid, engine_pid, edr_pid)

def upload_to_azure(args, src, dest, verbose=True):
    dest = f'{args.app_version}/{args.release_ring}/{args.date}/{args.machine_guid}/{dest}'
    if verbose:
        log.info(f'Uploading {src} to azure')
    if run_with_output(f'az storage blob  upload --account-name {args.account_name} --account-key {args.account_key} --container-name {args.container_name} --file {src} --name {dest}'):
        if verbose:
            log.info('Successfully uploaded to azure')
    elif verbose:
        log.error('Unable to upload to azure')

def collect_logs(logs_path, args):
    log.info("Running mdatp diagnostics")
    diagnostic_output = collect_mde_diagnostic(None)

    diagnostic_zip = os.path.join(logs_path, f'mde_diagnostic_{get_time_string(datetime.datetime.utcnow())}.zip')

    if not shutil.move(diagnostic_output['mde_diagnostic.zip'], diagnostic_zip):
        log.error(f"cannot copy {diagnostic_output['mde_diagnostic.zip']} to {logs_path}")
        return False

    upload_to_azure(args, diagnostic_zip, os.path.basename(diagnostic_zip))
    upload_to_azure(args, log.handlers[0].baseFilename, 'log.txt', False)

    return True

def print_args(args):
    args_dict = args.__dict__
    max_len = len(max(args_dict.keys(), key=len))
    for key, value in args_dict.items():
        log.info(f'{key}{" "*(max_len - len(key))} => {value}')

def observe_cpu_mem_spikes(args):
    AVG_MEM       = args.mem #KB
    AVG_CPU       = args.cpu #%

    args.app_version  = mdatp._get_health_parameter('app_version')
    args.release_ring = mdatp._get_health_parameter('release_ring')
    args.machine_guid = mdatp._get_health_parameter('machine_guid')
    args.date         = datetime.date.today().strftime("%b-%d-%Y")

    print_args(args)

    end_time = time.time() + args.duration.total_seconds()

    logs_path = "/tmp/processlogs/"
    os.makedirs(logs_path, exist_ok=True)
    daemon_pid, engine_pid, edr_pid = get_pids()

    log.info(f'Started monitoring the system with thresholds: {AVG_MEM/1000}MB memory and {AVG_CPU}% CPU')
    while time.time() < end_time:
        last_daemon_pid = daemon_pid
        last_engine_pid = engine_pid
        last_edr_pid = edr_pid
        daemon_pid, engine_pid, edr_pid = get_pids()

        if not daemon_pid and not engine_pid and not edr_pid:
            log.error("MDE process not found")
            collect_logs(logs_path, args)

        if daemon_pid != last_daemon_pid or engine_pid != last_engine_pid or edr_pid != last_edr_pid:
            log.error("One of the MDE process pid changed")
            collect_logs(logs_path, args)
        else:
            data = {}
            engine_ps_output = run_with_output(f'ps -p {engine_pid} -o rss=,%cpu=')
            engine_mem_rss_in_kb, engine_percentage_cpu_use = map(float, engine_ps_output.split())
            data['engine'] = {'mem':engine_mem_rss_in_kb, 'cpu': engine_percentage_cpu_use}

            daemon_ps_output = subprocess.check_output(['ps', '-p', str(daemon_pid), '-o', 'rss=,%cpu=']).decode()
            daemon_mem_rss_in_kb, daemon_percentage_cpu_use = map(float, daemon_ps_output.split())
            data['daemon'] = {'mem':daemon_mem_rss_in_kb, 'cpu': daemon_percentage_cpu_use}

            edr_ps_output = subprocess.check_output(['ps', '-p', str(edr_pid), '-o', 'rss=,%cpu=']).decode()
            edr_mem_rss_in_kb, edr_percentage_cpu_use = map(float, edr_ps_output.split())
            data['edr'] = {'mem':edr_mem_rss_in_kb, 'cpu': edr_percentage_cpu_use}

            mem_issues = {k:v for(k,v) in data.items() if v['mem'] > AVG_MEM}
            if mem_issues:
                log.error(f"High memory consumption in mde process: {mem_issues}")

            cpu_issues = {k:v for(k,v) in data.items() if v['cpu'] > AVG_CPU}
            if cpu_issues:
                log.error(f"High CPU utilization in mde process: {cpu_issues}")

            if cpu_issues or mem_issues:
                collect_logs(logs_path, args)

        time.sleep(args.sampling_rate)
