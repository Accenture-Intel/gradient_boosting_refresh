import io, logging, re, sh, subprocess, tempfile, glob, os, pprint, socket
from .merged_config import get_mdatp_config_allchannel
from pathlib import Path
from .audit_log_analyzer import AuditLogAnalyzer
from .ebpf_analyzer import EbpfAnalyzer
from .mdatp import mdatp
import json
from .machine import os_details, machine
from mde_tools import constants
from .utils import collect_mde_conflicts, get_time_string, collect_running_conflicting_binaries,\
        collect_non_mdatp_auditd_rules, collect_extended_attribute_info, collect_dlp_classification_policy,\
        collect_dlp_enforcement_policy, wrap_function_log_exception, create_zip, run_with_output, command_exists,\
        modify_ld_path, collect_command_output_to_file
import itertools
import operator

diagnostic_functions = dict()
log = logging.getLogger(constants.LOGGER_NAME)
os_info = os_details()
new_env = modify_ld_path()

def register_diagnostic_collection_func(collection_name=None, platform=None, required_package=None):
    """Register diagnostic collection function to execute upon diagnostic collection scenario.
       collection_name str: The name to put in the collection, defaults to function name
       platform str: Platform to run the data collection on. Should use constants, such as constants.LINUX_PLATFORM or MACOS_PLATFORM.
                     Will default to all platforms if not provided

       Each function should output the following structure:
       {"crashes/": ["/tmp/crash1.log", "/tmp/crash2.log"]}
       Dictionary where each key should be the destination path in the output directory
       The value should be a path (or list of paths) of files to copy to the output directory.
       When creating files, it's better to create temporary files using `tempfile.mkstemp` so files will be created in non-persistent non-visible directories.
    """
    def decorator(func):
        # Use collection_name if supplied, otherwise use function name
        if required_package and command_exists(required_package) == False:
            log.warn(f'Skipping data collector function [{collection_name}] as {required_package} is not installed')
            return func

        if platform == os_info.platform or not platform:
            diagnostic_functions[collection_name if collection_name else func.__name__] = func
        return func
    return decorator

@register_diagnostic_collection_func('MDE Diagnostic', required_package='mdatp')
def collect_mde_diagnostic(args):
    def fallback_logs():
        dirs = list({constants.LOG_DIR[os_info.platform],
                os.path.dirname(constants.WDAV_STATE[os_info.platform]),
                os.path.dirname(constants.WDAV_CFG[os_info.platform])})
        _, diagnostics_zip = tempfile.mkstemp(prefix=f'diagnostics_{get_time_string()}', suffix='.zip')
        create_zip(diagnostics_zip, path=dirs, retain_dir_tree=True, recursive=True)
        return diagnostics_zip
    diagnostic = mdatp.collect_logs(copy_to_collection=False)
    if not diagnostic:
        log.warn('Failed to create MDE diagnostic zip using the mdatp command. Generating manually.')
        diagnostic = fallback_logs()
    log.info('Successfully created MDE diagnostic zip')
    return {'mde_diagnostic.zip' : diagnostic}

# TODO: Soon MDATP health will be part of diagnostics, we can remove after this change
@register_diagnostic_collection_func('MDE Health', required_package='mdatp')
def collect_mde_health(args):
    health_data = mdatp.health_data()
    if not health_data:
        log.warn("Failed to collect MDE health")
        return
    _, health_path = tempfile.mkstemp(prefix=f'mde_health_{get_time_string()}', suffix='.txt')
    with open(health_path, 'w') as writer:
        writer.write(health_data)
    return {'health.txt': health_path}

@register_diagnostic_collection_func('MDE Health Features', required_package='mdatp')
def collect_mde_health_features(args):
    health_features_data = mdatp.health_features_data()
    if not health_features_data:
        log.warn("Failed to collect MDE health features")
        return
    _, health_features_path = tempfile.mkstemp(prefix=f'mde_health_features{get_time_string()}', suffix='.txt')
    with open(health_features_path, 'w') as writer:
        writer.write(health_features_data)
    return {'health_details_features.txt': health_features_path}

@register_diagnostic_collection_func('DLP Health', constants.MACOS_PLATFORM, required_package='mdatp')
def collect_dlp_health(args):
    dlp_health_data = mdatp.dlp_health_data()
    if not dlp_health_data:
        log.warn("Failed to collect DLP health: mdatp health --details data_loss_prevention")
        return
    _, dlp_health_path = tempfile.mkstemp(prefix=f'dlp_health_{get_time_string()}', suffix='.txt')
    with open(dlp_health_path, 'w') as writer:
        writer.write(dlp_health_data)
    return {'dlp_health.txt': dlp_health_path}

@register_diagnostic_collection_func('MDE Permissions', required_package='mdatp')
def collect_mde_Permissions(args):
    health_permissions_data = mdatp.health_permissions_data()
    if not health_permissions_data:
        log.warn("Failed to collect MDE health --details permissions")
        return
    _, health_permission_path = tempfile.mkstemp(prefix=f'mde_health_permissions{get_time_string()}', suffix='.txt')
    with open(health_permission_path, 'w') as writer:
        writer.write(health_permissions_data)
    return {'permissions.txt': health_permission_path}

# @register_diagnostic_collection_func('MDE antivirus-engine-pool-content', required_package='mdatp')
# def collect_mde_antivirus_engine_pool_content(args):
#     collect_engine_pool_content_data = mdatp.collect_engine_pool_content()
#     if not collect_engine_pool_content_data:
#         log.warn("Failed to collect MDE diagnostic antivirus-engine-pool-content --time 10")
#         return
#     _, collect_engine_pool_content_path = tempfile.mkstemp(prefix=f'mde_engine_pool_content_{get_time_string()}', suffix='.txt')
#     print(collect_engine_pool_content_path)
#     with open(collect_engine_pool_content_path, 'w') as writer:
#         writer.write(collect_engine_pool_content_data)
#     return {'engine_core_pool_content.txt': collect_engine_pool_content_path}

@register_diagnostic_collection_func('macOS Syslog', constants.MACOS_PLATFORM)
def collect_macos_syslog(args):
    log.info(f"   Collect last 1h syslog")
    output = io.StringIO()
    sh.log('show','--debug','--info','--style','compact','--color','none','-last', '1h', _out=output, _env=new_env)
    _, syslog_path = tempfile.mkstemp(prefix=f'syslog_{get_time_string()}', suffix='.txt')
    with open(syslog_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'syslog.txt': syslog_path}

@register_diagnostic_collection_func('macOS BTM', constants.MACOS_PLATFORM)
def collect_macos_dumpbtm(args):
    log.info(f"   Collect sytem BTM")
    output = io.StringIO()
    sh.sfltool('dumpbtm', _out=output, _env=new_env)
    _, log_path = tempfile.mkstemp(prefix=f'bumpbtm_{get_time_string()}', suffix='.txt')
    with open(log_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'dumpbtm.txt': log_path}

@register_diagnostic_collection_func('macOS wdavdaemon process vmmap', constants.MACOS_PLATFORM, required_package='mdatp')
def collect_macos_wdavdaemon_process_vmmap(args):
    log.info(f"   Collect vmmap of MDE processes")
    temp = tempfile.mkdtemp(prefix="mde_process_vmmap_")
    mdatp.vmmap_wdavdaemon_processes(temp)
    file_list = {}
    for f in glob.glob(os.path.join(temp, "*")):
        file_list[os.path.basename(f)] = f
    return file_list
    
@register_diagnostic_collection_func('macOS process sampling', constants.MACOS_PLATFORM, required_package='mdatp')
def collect_macos_edr_process_sampling(args):
    log.info(f"   Collect sampling of MDE EDR processes")
    temp = tempfile.mkdtemp(prefix="mde_process_sampling_")
    mdatp.sample_edr_processes(temp)
    file_list = {}
    for f in glob.glob(os.path.join(temp, "*")):
        file_list[os.path.basename(f)] = f
    return file_list

@register_diagnostic_collection_func('macOS netext debug syslog', constants.MACOS_PLATFORM)
def collect_macos_netext_debug_syslog(args):
    try:
        time_to_collect = args.length
    except AttributeError:
        time_to_collect = 30 # default
    log.info(f"   Collect {time_to_collect}s netext debug syslog")
    output = io.StringIO()
    sh.log('stream','--debug','--info','--style','compact','--color','none','--timeout', f'{time_to_collect}s', '-predicate', 'process CONTAINS "netext"', _out=output, _env=new_env)
    _, syslog_path = tempfile.mkstemp(prefix=f'syslog_netext_{get_time_string()}', suffix='.txt')
    with open(syslog_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'syslog_netext_30s_realtime.txt': syslog_path}

@register_diagnostic_collection_func('macOS epsext debug syslog', constants.MACOS_PLATFORM)
def collect_macos_epsext_debug_syslog(args):
    try:
        time_to_collect = args.length
    except AttributeError:
        time_to_collect = 30 # default
    log.info(f"   Collect {time_to_collect}s epsext debug syslog")
    output = io.StringIO()
    sh.log('stream','--debug','--info','--style','compact','--color','none','--timeout', f'{time_to_collect}s', '-predicate', 'process CONTAINS "epsext"', _out=output, _env=new_env)
    _, syslog_path = tempfile.mkstemp(prefix=f'syslog_epsext_{get_time_string()}', suffix='.txt')
    with open(syslog_path, 'w') as writer:
        writer.write(output.getvalue())
    output1 = io.StringIO()
    date_command = ["date", "-v", "-48H", "+%Y-%m-%d %H:%M:%S"]
    date_output = subprocess.check_output(date_command).decode().strip()
    sh.log('show','--start', date_output,'--info','--color','none', '--predicate','process == "epsext"', _out=output1, _env=new_env)
    _, syslog2d_path = tempfile.mkstemp(prefix=f'syslog_epsext_{get_time_string()}', suffix='.txt')
    with open(syslog2d_path, 'w') as writer:
        writer.write(output1.getvalue())
    return {'syslog_epsext_30s_realtime.txt': syslog_path, 'syslog_epsext_2day_info.txt': syslog2d_path}

@register_diagnostic_collection_func('MDE Crashes Information', required_package='mdatp')
def collect_mde_crashes(args):
    crashes = mdatp.collect_crash_logs(["wdavdaemon", "telemetryd", "telemetryd_v2"], copy_to_collection=False)
    if not crashes:
        log.info('No crash dumps or logs found')
        return
    return {'crashes/': crashes}

@register_diagnostic_collection_func('Process Information')
def collect_process_information(args):
    fp_flag="w"
    process_data = io.StringIO()
    if os_info.platform == constants.LINUX_PLATFORM:
        sh.ps("axo", "pid,ppid,user,%cpu,%mem,vsz,rss,tty,stat,start,time,command", _out=process_data, _env=new_env)
    else:
        process_data = io.BytesIO()
        fp_flag="wb"
        sh.ps("auxww", "-o", "pid,ppid,user,%cpu,%mem,vsz,rss,tty,stat,start,time,command", _out=process_data, _env=new_env)
    _, processes_data_path = tempfile.mkstemp(prefix=f'processes_info_{get_time_string()}', suffix='.txt')
    with open(processes_data_path, fp_flag) as writer:
        writer.write(process_data.getvalue())
    return {'process_information.txt': processes_data_path}

@register_diagnostic_collection_func('Launchd Information', constants.MACOS_PLATFORM)
def collect_launchd_information(args):
    process_data = io.BytesIO()
    sh.launchctl("dumpstate", _out=process_data, _env=new_env)
    _, processes_data_path = tempfile.mkstemp(prefix=f'launchd_dumpstate_{get_time_string()}', suffix='.txt')
    with open(processes_data_path, "wb") as writer:
        writer.write(process_data.getvalue())
    return {'launchd_dumpstate.txt': processes_data_path}

@register_diagnostic_collection_func('Proc Directory', constants.LINUX_PLATFORM, required_package='mdatp')
def collect_proc_directory(args):
    #create tmp file for output
    _, processes_data_path = tempfile.mkstemp(prefix=f'proc_directory_info_{get_time_string()}', suffix='.txt')
    
    #get mdatp pids
    mdatp_processes = mdatp.get_mdatp_processes()
    mdatp_pids = [x[0] for x in mdatp_processes]
    
    #iterate over pids and collect /proc/$pid/*
    with open(processes_data_path, 'w') as writer:
        for pid in mdatp_pids:
                proc_maps = io.StringIO()
                sh.cat("/proc/" + pid + "/maps", _out=proc_maps, _env=new_env)
                writer.write(proc_maps.getvalue())
                writer.write("------------------------------------------------\n\n")
    return {'proc_directory_info.txt': processes_data_path}

@register_diagnostic_collection_func('AuditD information', constants.LINUX_PLATFORM, required_package='auditd')
def collect_auditd_information(args):
    audit_version = mdatp.auditd_version()
    audit_status = mdatp.auditd_status(full=True)
    audit_conf = '\n\n'.join([mdatp.auditctl_status(), mdatp.auditd_conf(), mdatp.audispd_conf()]);
    keywords = ['auditd', 'augenrules', 'auditctl','sudo cat /var/log/syslog', 'sudo cat /var/log/messsages', '==========']
    lines = mdatp.auditd_syslog().split('\n')
    audit_loaded_rules = mdatp.auditd_loaded_rules()
    audit_deployed_rules = mdatp.auditd_deployed_rules()
    audit_deployed_plugins = mdatp.auditd_deployed_plugins()
    audisp_deployed_rules = mdatp.audisp_deployed_rules()
    audisp_deployed_plugins = mdatp.audisp_deployed_plugins()
    audit_syslog = '\n'.join([line for line in lines if any ([expr in line for expr in keywords])])
    non_mdatp_rules = collect_non_mdatp_auditd_rules(audit_loaded_rules)

    if not audit_status:
        log.warn("Failed to collect AuditD information")
        return

    #TODO: analyse conflicting rules

    _, auditd_data_path = tempfile.mkstemp(prefix=f'auditd_info_{get_time_string()}', suffix='.txt')
    with open(auditd_data_path, 'w', encoding='utf-8') as writer:
        writer.write('\n\n'.join([audit_version, audit_status, audit_conf, audit_loaded_rules, non_mdatp_rules,
                                  audit_deployed_rules, audit_deployed_plugins,
                                  audisp_deployed_rules, audisp_deployed_plugins,
                                  audit_syslog]))
    return {'auditd_info.txt': auditd_data_path}


@register_diagnostic_collection_func('AuditD analysis', constants.LINUX_PLATFORM, required_package='auditd')
def collect_auditd_log(args):
    directory = Path('/var/log/audit/')
    log_files = [file for file in directory.iterdir() if file.is_file()]
    analyzer = AuditLogAnalyzer()

    for log in log_files:
        analyzer.analyze(log)

    _, auditd_data_path = tempfile.mkstemp(prefix=f'auditd_log_{get_time_string()}', suffix='.txt')

    analyzer.write_to(auditd_data_path)

    _, auditd_logs_zip = tempfile.mkstemp(prefix=f'auditd_logs_{get_time_string()}', suffix='.zip')
    create_zip(auditd_logs_zip, path=directory, zipdir='auditd_logs')

    return {'auditd_log_analysis.txt': auditd_data_path,
            'auditd_logs.zip' : auditd_logs_zip}

@register_diagnostic_collection_func('Ebpf Info', constants.LINUX_PLATFORM)
def collect_ebpf_info(args):
    analyzer = EbpfAnalyzer()
    analyzer.collect_kernel_configurations()
    analyzer.collect_enabled_functions()
    _, ebpf_syscalls_zip = tempfile.mkstemp(prefix=f'ebpf_syscalls_{get_time_string()}', suffix='.zip')
    create_zip(ebpf_syscalls_zip, path=constants.EBPF_SYSCALLS, zipdir='ebpf_sycalls', recursive=True, retain_dir_tree=True)

    _, ebpf_raw_syscalls_zip = tempfile.mkstemp(prefix=f'ebpf_raw_syscalls_{get_time_string()}', suffix='.zip')
    create_zip(ebpf_raw_syscalls_zip, path=constants.EBPF_RAW_SYSCALLS, zipdir='ebpf_raw_syscalls', recursive=True, retain_dir_tree=True)

    return {'ebpf_kernel_config.txt': analyzer.kernel_configurations,
            'ebpf_enabled_func.txt' : analyzer.enabled_functions, 
            'ebpf_syscalls.zip' :ebpf_syscalls_zip , 
            'ebpf_raw_syscalls.zip': ebpf_raw_syscalls_zip}

    
@register_diagnostic_collection_func('Collecting syslog/messages', constants.LINUX_PLATFORM)
def collect_syslog(args):
    base_log_file = None
    if os.path.exists('/var/log/syslog'):
        base_log_file = '/var/log/syslog'
    elif os.path.exists('/var/log/messages'):
        base_log_file = '/var/log/messages'
    else:
        raise RuntimeError('Neither [/var/log/syslog] nor [/var/log/messages] exists')

    filename = os.path.basename(base_log_file)
    _, logs_zip = tempfile.mkstemp(prefix=f'{filename}_{get_time_string()}', suffix='.zip')

    create_zip(logs_zip, path=os.path.dirname(base_log_file), prefix_pattern=filename, zipdir=filename + 's')

    return {f'{filename}s.zip' : logs_zip}


@register_diagnostic_collection_func('MDE Conflicting Processes', constants.LINUX_PLATFORM)
def collect_mde_conflicting_agents(args):
    _, conflicting_processes_file = tempfile.mkstemp(prefix=f'conflicting_processes_{get_time_string()}', suffix='.txt')
    conflicts = "No Known Conflicts"
    conflicting_agents, _ = collect_mde_conflicts()
    conflicting_binaries = []
    if os_info.platform == constants.LINUX_PLATFORM:
        if command_exists('auditd'): 
            conflicting_binaries = collect_running_conflicting_binaries(mdatp.auditd_loaded_rules())
        else:
            log.warn(f'Not able to collect conflicting binaries as auditd is not installed')
    if len(conflicting_agents) > 0 or len(conflicting_binaries) > 0:
        conflicts = '\n\n'.join([conflicting_agents, conflicting_binaries])
    with open(conflicting_processes_file, 'w') as writer:
        writer.write(conflicts)
    return {'conflicting_processes_information.txt': conflicting_processes_file}

@register_diagnostic_collection_func('MDE Exclusions', required_package='mdatp')
def collect_mde_exclusions(args):
    exclusions_data = mdatp.get_exclusions()
    if not exclusions_data:
        log.warn("Failed to collect MDE exclusions")
        return
    _, exclusions_path = tempfile.mkstemp(prefix=f'mde_exclusions_{get_time_string()}', suffix='.txt')
    with open(exclusions_path, 'w') as writer:
        writer.write(exclusions_data)
    return {'exclusions.txt': exclusions_path}

@register_diagnostic_collection_func('MDE Definitions Details', required_package='mdatp')
def collect_mde_definitions_details(args):
    definitions_data = mdatp.definitions_data()
    if not definitions_data:
        log.warn("Failed to collect MDE Definitions details")
        return
    _, definitions_path = tempfile.mkstemp(prefix=f'mde_definitions_{get_time_string()}', suffix='.txt')
    with open(definitions_path, 'w') as writer:
        writer.write(definitions_data)
    return {'definitions.txt': definitions_path}

@register_diagnostic_collection_func('MDE Directories List', required_package='mdatp')
def collect_mde_user_information(args):
    output = io.StringIO()
    mde_dirs = mdatp.get_mde_directories()
    for mde_dir in mde_dirs:
        try:
            sh.ls("-lR", mde_dir, _out=output, _env=new_env)
        except:
            output.write(f"Could not list directory '{mde_dir}'")

    if os_info.platform == constants.LINUX_PLATFORM:
        try:
            sh.stat("/var", _out=output, _env=new_env)
            sh.stat("/var/log", _out=output, _env=new_env)
            sh.stat("/var/log/microsoft", _out=output, _env=new_env)
            sh.stat("/var/log/microsoft/mdatp", _out=output, _env=new_env)
        except:
            output.write("Could not stat log dirs")

    _, mde_dirs_path = tempfile.mkstemp(prefix=f'mde_directories_{get_time_string()}', suffix='.txt')

    with open(mde_dirs_path, 'w') as writer:
        writer.write(output.getvalue())

    return {'mde_directories.txt': mde_dirs_path}

@register_diagnostic_collection_func('DLP Enforcement Policy', constants.MACOS_PLATFORM, required_package='mdatp')
def policy_info(args):
    output = collect_dlp_enforcement_policy()
    _, dlp_enforcement_policy_path = tempfile.mkstemp(prefix=f'dlp_enforcement_policy{get_time_string()}', suffix='.txt')
    with open(dlp_enforcement_policy_path, 'w') as writer:
        writer.write(output)
    return {'dlp_enforcement_policy.txt': dlp_enforcement_policy_path}

@register_diagnostic_collection_func('DLP Classification Policy', constants.MACOS_PLATFORM, required_package='mdatp')
def classification_info(args):
    output = collect_dlp_classification_policy()
    _, dlp_classification_policy_path = tempfile.mkstemp(prefix=f'dlp_classification_policy{get_time_string()}', suffix='.txt')
    with open(dlp_classification_policy_path, 'w') as writer:
        writer.write(output)
    return {'dlp_classification_policy.txt': dlp_classification_policy_path}

@register_diagnostic_collection_func('Extended Attribute Info', constants.MACOS_PLATFORM, required_package='mdatp')
def extended_attribute_info(args):
    output = collect_extended_attribute_info(args)
    _, dlp_file_extended_attribute_path = tempfile.mkstemp(prefix=f'dlp_file_extended_attribute{get_time_string()}', suffix='.txt')
    with open(dlp_file_extended_attribute_path, 'w') as writer:
        writer.write(output)
    return {'dlp_file_extended_attribute.txt': dlp_file_extended_attribute_path}

@register_diagnostic_collection_func('Disk Usage')
def collect_disk_usage_information(args):
    output = io.StringIO()
    sh.df("-h", _out=output, _env=new_env)
    _, disk_usage_path = tempfile.mkstemp(prefix=f'disk_usage_{get_time_string()}', suffix='.txt')
    with open(disk_usage_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'disk_usage.txt': disk_usage_path}

@register_diagnostic_collection_func('MDE User Info', required_package='mdatp')
def collect_mde_user_information(args):
    if os_info.platform == constants.LINUX_PLATFORM:
        user = 'mdatp'
    else:
        user = '_mdatp'
    output = io.StringIO()
    sh.id(user, _out=output, _env=new_env)
    _, mde_user_path = tempfile.mkstemp(prefix=f'mde_user_{get_time_string()}', suffix='.txt')
    with open(mde_user_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'mde_user.txt': mde_user_path}

@register_diagnostic_collection_func('MDE Definitions Mount Point', constants.LINUX_PLATFORM, required_package='mdatp')
def collect_mde_definitions_mount_points(args):
    output = io.StringIO()
    mde_definitions = mdatp.get_database_root()
    output.write('Definitions mount point:\n')
    sh.findmnt("-n", "--target", mde_definitions, _out=output, _env=new_env)

    _, mde_definitions_mount_path = tempfile.mkstemp(prefix=f'mde_definitions_mount_{get_time_string()}', suffix='.txt')
    with open(mde_definitions_mount_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'mde_definitions_mount.txt': mde_definitions_mount_path}

@register_diagnostic_collection_func('MDE Service Status', constants.LINUX_PLATFORM, required_package='mdatp')
def collect_mde_service_status(args):
    output = io.StringIO()
    sh.service("mdatp", "status", _out=output, _encoding='utf-8', _env=new_env)
    _, service_status_path = tempfile.mkstemp(prefix=f'service_status_{get_time_string()}', suffix='.txt')
    with open(service_status_path, 'w', encoding='utf-8') as writer:
        writer.write(output.getvalue())
    return {'service_status.txt': service_status_path}

@register_diagnostic_collection_func('MDE Service File', constants.LINUX_PLATFORM, required_package='mdatp')
def collect_mde_service_file(args):
    output = io.StringIO()
    abs_path = ''
    if os.path.exists(constants.MDATP_SERVICE_PATH_DEB):
        abs_path = constants.MDATP_SERVICE_PATH_DEB
    elif os.path.exists(constants.MDATP_SERVICE_PATH_RPM):
        abs_path = constants.MDATP_SERVICE_PATH_RPM
    if os.path.exists(abs_path):
        _, service_file_path = tempfile.mkstemp(prefix=f'service_file_{get_time_string()}', suffix='.txt')
        sh.cp(abs_path, service_file_path, _env=new_env)
    else:
        log.warn('Not able to get mdatp.sevice file')
    return {'service_file.txt': service_file_path}

@register_diagnostic_collection_func('Hardware Information')
def collect_hardware_information(args):
    output = io.StringIO()
    if os_info.platform == constants.MACOS_PLATFORM:
        sh.ioreg("-l", "-w 0", _out=output, _decode_errors="ignore", _env=new_env)
    else:
        sh.lshw(_out=output, _env=new_env) # Not installed by default on RHEL, may throw.
    _, hardware_info_path = tempfile.mkstemp(prefix=f'hardware_info_{get_time_string()}', suffix='.txt')
    with open(hardware_info_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'hardware_info.txt': hardware_info_path}

@register_diagnostic_collection_func('Bluetooth Information', constants.MACOS_PLATFORM)
def collect_bluetooth_information(args):
    output = io.StringIO()
    sh.system_profiler("SPBluetoothDataType", _out=output, _decode_errors="ignore", _env=new_env)
    _, bluetooth_info_path = tempfile.mkstemp(prefix=f'bluetooth_info_{get_time_string()}', suffix='.txt')
    with open(bluetooth_info_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'bluetooth_info.txt': bluetooth_info_path}

@register_diagnostic_collection_func('Mount Info')
def collect_mount_information(args):
    return collect_command_output_to_file('mount', 'mount.txt', 'mount', new_env)

@register_diagnostic_collection_func('Uname Info')
def collect_uname_information(args):
    output = io.StringIO()
    sh.uname("-a", _out=output, _env=new_env)
    _, uname_path = tempfile.mkstemp(prefix=f'uname_{get_time_string()}', suffix='.txt')
    with open(uname_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'uname.txt': uname_path}

@register_diagnostic_collection_func('Memory Info')
def collect_memory_information(args):
    if os_info.platform == 'macOS':
        command = "memory_pressure"
    else:
        command = "free"
    return collect_command_output_to_file('memory', 'memory.txt', command, new_env)

@register_diagnostic_collection_func('Meminfo command')
def collect_meminfo(args):
    output = io.StringIO()
    if os_info.platform == 'macOS':
        sh.vm_stat(_out=output, _env=new_env)
    else:
        sh.cat("/proc/meminfo", _out=output, _env=new_env)
    _, memory_path = tempfile.mkstemp(prefix=f'meminfo_{get_time_string()}', suffix='.txt')
    with open(memory_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'meminfo.txt': memory_path}

@register_diagnostic_collection_func('CPU Info')
def collect_cpu_information(args):
    output = io.StringIO()
    if os_info.platform == 'macOS':
        sh.grep(sh.sysctl('-a', _env=new_env), 'machdep.cpu',  _out=output, _env=new_env)
    else:
        sh.lscpu(_out=output, _env=new_env)
    _, memory_path = tempfile.mkstemp(prefix=f'cpuinfo_{get_time_string()}', suffix='.txt')
    with open(memory_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'cpuinfo.txt': memory_path}

@register_diagnostic_collection_func('MDE Open File Descriptors Info', required_package='mdatp')
def collect_file_descriptors_information(args):
    return collect_command_output_to_file('lsof', 'lsof.txt', 'lsof', new_env)

@register_diagnostic_collection_func('SELinux Status Info', constants.LINUX_PLATFORM)
def collect_sestatus_information(args):
    return collect_command_output_to_file('sestatus', 'sestatus.txt', 'sestatus', new_env)

@register_diagnostic_collection_func('lsmod Info', constants.LINUX_PLATFORM)
def collect_lsmod_information(args):
    return collect_command_output_to_file('lsmod', 'lsmod.txt', 'lsmod', new_env)

@register_diagnostic_collection_func('dmesg Info', constants.LINUX_PLATFORM)
def collect_dmesg_information(args):
    output = io.StringIO()
    try:
        sh.dmesg("-T", _out=output, _env=new_env)
    except:
        output.write("Could not run dmesg -T command")

    _, dmesg_info_path = tempfile.mkstemp(prefix=f'dmesg_info_{get_time_string()}', suffix='.txt')
    with open(dmesg_info_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'dmesg.txt': dmesg_info_path}

@register_diagnostic_collection_func('kernel lockdown Info', constants.LINUX_PLATFORM)
def collect_kernel_lockdown_information(args):
    output = io.StringIO()
    try:
        sh.cat("/sys/kernel/security/lockdown", _out=output, _env=new_env)
    except:
        output.write("Could not run cat /sys/kernel/security/lockdown")

    _, kernel_lockdown_info_path = tempfile.mkstemp(prefix=f'kernel_lockdown_info_{get_time_string()}', suffix='.txt')
    with open(kernel_lockdown_info_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'kernel_lockdown.txt': kernel_lockdown_info_path}

@register_diagnostic_collection_func('lsmod Info', constants.LINUX_PLATFORM)
def collect_lsmod_information(args):
    output = io.StringIO()
    sh.lsmod(_out=output, _env=new_env)
    _, lsmod_path = tempfile.mkstemp(prefix=f'lsmod_{get_time_string()}', suffix='.txt')
    with open(lsmod_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'lsmod.txt': lsmod_path}

@register_diagnostic_collection_func('System Extensions Info', constants.MACOS_PLATFORM)
def collect_system_extensions_information(args):
    if re.match("10.14.*", os_info.version) is not None:
        return
    output = io.StringIO()
    sh.csrutil('status', _out=output, _env=new_env)
    sh.systemextensionsctl("list", _out=output, _env=new_env)
    _, system_extensions_path = tempfile.mkstemp(prefix=f'system_extensions_{get_time_string()}', suffix='.txt')
    with open(system_extensions_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'system_extensions.txt': system_extensions_path}

@register_diagnostic_collection_func('machine info commands')
def collect_machine_info(args):
    diag_functions = [('top','-l','1','-o','cpu'),
                        ('nettop','-l','1'),
                        ('fs_usage','-t','1')] if (os_info.platform == 'macOS') else [('top','-c', '-n','1','b', '-w', '512')]
    results = {}
    for func in diag_functions:
        output = io.StringIO()
        cmd = sh.Command(func[0])
        cmd(*func[1:], _out=output, _decode_errors="ignore", _env=new_env)
        with tempfile.NamedTemporaryFile(delete=False,mode='wt', prefix=f'{func[0]}_{get_time_string()}', suffix='.txt') as f:
            f.write(output.getvalue())
            results[f'{func[0]}.txt'] = f.name
    return results


@register_diagnostic_collection_func('TCC DB info', constants.MACOS_PLATFORM)
def collect_tcc_db_information(args):
    if re.match("10.14.*", os_info.version) is not None:
        # we don't need to get this on Mojave
        return
    output = io.StringIO()
    sql_string = "service,client,client_type,allowed"
    if os_info.is_big_sur_and_up():
        sql_string = "service,client,client_type,auth_value,auth_reason"

    sh.sqlite3('/Library/Application Support/com.apple.TCC/TCC.db', 'select ' + sql_string + ' from access', _out=output, _env=new_env)
    _, tcc_db_path = tempfile.mkstemp(prefix=f'tcc_db_{get_time_string()}', suffix='.txt')
    with open(tcc_db_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'tcc_db.txt': tcc_db_path}

@register_diagnostic_collection_func('Mac system profiler information', constants.MACOS_PLATFORM)
def collect_mac_system_profiler(args):
    output = io.StringIO()
    sh.system_profiler("-json", _out=output, _env=new_env)
    _, system_profiler_path = tempfile.mkstemp(prefix=f'system_profiler_{get_time_string()}', suffix='.json')
    with open(system_profiler_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'system_profiler.txt': system_profiler_path}

@register_diagnostic_collection_func('Memory Leaks Info', constants.MACOS_PLATFORM, required_package='mdatp')
def collect_memory_leaks_information(args):
    output = io.StringIO()
    processes = mdatp.get_mdatp_processes()
    for process in processes:
        pid, command = process
        if not "ext" in command and not "wdavdaemon privileged" in command: #querying leaks on privileged daemon renders the machine unusable
            output.write(f"Leaks output for process '{command}':\n")
            try:
                sh.leaks(pid, _out=output, _env=new_env)
            except Exception as e:
                output.write(f"Exception during leaks execution {e}\n")
    _, memory_leaks_path = tempfile.mkstemp(prefix=f'memory_leaks_{get_time_string()}', suffix='.txt')
    with open(memory_leaks_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'memory_leaks.txt': memory_leaks_path}

@register_diagnostic_collection_func('rtp statistics', required_package='mdatp')
def collect_rtp_statistics(args):
    rtp_stats = mdatp.rtp_statistics()
    _, rtp_path = tempfile.mkstemp(prefix=f'rtp_statistics_{get_time_string()}', suffix='.txt')
    with open(rtp_path, 'w') as writer:
        writer.write(rtp_stats)
    return {'rtp_statistics.txt': rtp_path}

@register_diagnostic_collection_func('libc information', constants.LINUX_PLATFORM)
def collect_libc_info(args):
    # On debian the library is called libc6, on rhel its glibc
    libc_package_info = [machine.query_installed_package('libc6'), machine.query_installed_package('glibc')]
    _, log_path = tempfile.mkstemp(prefix=f'libc_info_{get_time_string()}', suffix='.txt')
    with open(log_path, 'w') as outfile:
        for package in libc_package_info:
            if package.installed == True: 
                outfile.write(str(package))
    return {'libc_info.txt': log_path}

@register_diagnostic_collection_func('Uptime Info')
def collect_uptime_info(args):
    return collect_command_output_to_file('uptime_info', 'uptime_info.txt', 'uptime', new_env)

@register_diagnostic_collection_func('Last info')
def collect_macos_syslog(args):
    return collect_command_output_to_file('last_info', 'last_info.txt', 'last', new_env)

@register_diagnostic_collection_func('Locale Information')
def collect_locale_information(args):
    output = io.StringIO()
    output.write('localectl status:\n')
    wrap_function_log_exception(lambda: sh.localectl("status",_out=output, _env=new_env))
    output.write('\nlocale:\n')
    wrap_function_log_exception(lambda: sh.locale(_out=output, _env=new_env))
    output.write('\nlocale -c charmap:\n')
    wrap_function_log_exception(lambda: sh.locale("-c", "charmap", _out=output, _env=new_env))
    output.write('\nlocale -a:\n')
    wrap_function_log_exception(lambda: sh.locale("-a", _out=output, _env=new_env))
    output.write('\nlocale -m:\n')
    wrap_function_log_exception(lambda: sh.locale("-m", _out=output, _env=new_env))
    
    _, locale_info_path = tempfile.mkstemp(prefix=f'locale_info_{get_time_string()}', suffix='.txt')
    with open(locale_info_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'locale_info.txt': locale_info_path}

@register_diagnostic_collection_func('/tmp files owned by group:mdatp', constants.LINUX_PLATFORM, required_package='mdatp')
def collect_tmp_file_owned_by_mdatp(args):
    output = io.StringIO()
    #sudo find /tmp -group mdatp | xargs du -sh | sort -rh
    sh.sort(sh.xargs(sh.find('/tmp', '-group', 'mdatp', _env=new_env), 'du', '-sh', _env=new_env), '-rh', _out=output, _env=new_env)
    _, tmp_files_owned_by_mdatp = tempfile.mkstemp(prefix=f'tmp_files_owned_by_mdatp_{get_time_string()}', suffix='.txt')
    with open(tmp_files_owned_by_mdatp, 'w') as writer:
        writer.write(output.getvalue())
    return {'tmp_files_owned_by_mdatp.txt': tmp_files_owned_by_mdatp}

@register_diagnostic_collection_func('MDATP configurations', required_package='mdatp')
def collect_merged_config(args):
    output = get_mdatp_config_allchannel()
    if not output:
        log.warn("Failed to collect MDE MERGED config")
        return
    _, mdatp_config_path = tempfile.mkstemp(prefix=f'merged_config_{get_time_string()}', suffix='.txt')
    for each in output:
        with open(mdatp_config_path, 'a') as writer:
            writer.write(f"{each['description']}\n")
            writer.write(f"{each['title']}\n")
            writer.write(f"{each['filepath']}\n")
            if "value" in each:
                writer.write('\n')
                writer.write(json.dumps(each['value'], indent=4))
            elif "fileerror" in each:
                writer.write(f"Error: {each['fileerror']}")
            writer.write('\n\n\n')
    return {'mdatp_config.txt': mdatp_config_path}
    
@register_diagnostic_collection_func('Enginedb files', required_package='mdatp')
def collect_enginedb_file(args):
    db_files = dict()
    def _check_n_copy(f):
        abs_path = os.path.join(constants.ENGINEDB_DIR[os_info.platform], f)
        if os.path.exists(abs_path):
            _, tmp_file  = tempfile.mkstemp(prefix=f'{f}_{get_time_string()}', suffix=f".{f.split('.')[-1]}")
            sh.cp(abs_path, tmp_file, _env=new_env)
            db_files[f] = tmp_file

    _check_n_copy('mpenginedb.db')
    _check_n_copy('mpenginedb.db-wal')
    _check_n_copy('mpenginedb.db-shm')

    if not db_files:
        log.warn('No enginedb files exist')
    return db_files
    
@register_diagnostic_collection_func('Linux iptables rules', constants.LINUX_PLATFORM)
def collect_iptables_rules(args):
    output = io.StringIO()

    output.write('iptables -L -nv:\n')
    wrap_function_log_exception(lambda: sh.iptables("-L", "-n", "-v", _out=output, _env=new_env))
    output.write('iptables -L -nv -t nat:\n')
    wrap_function_log_exception(lambda: sh.iptables("-L", "-n", "-v", "-t", "nat", _out=output, _env=new_env))
    output.write('iptables -L -nv -t mangle:\n')
    wrap_function_log_exception(lambda: sh.iptables("-L", "-n", "-v", "-t", "mangle", _out=output, _env=new_env))
    output.write('iptables -L -nv -t raw:\n')
    wrap_function_log_exception(lambda: sh.iptables("-L", "-n", "-v", "-t", "raw", _out=output, _env=new_env))
    
    _, iptables_path = tempfile.mkstemp(prefix=f'iptables_rules_{get_time_string()}', suffix='.txt')
    with open(iptables_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'iptables_rules.txt': iptables_path}

@register_diagnostic_collection_func('Network information', constants.LINUX_PLATFORM)
def collect_network_info(args):
    output = io.StringIO()
    _, network_info_path = tempfile.mkstemp(prefix=f'network_info_{get_time_string()}', suffix='.txt')

    output.write('ip link show:\n')
    wrap_function_log_exception(lambda: sh.ip("link", "show", _out=output, _env=new_env))

    output.write('ip address show:\n')
    wrap_function_log_exception(lambda: sh.ip("address", "show", _out=output, _env=new_env))

    output.write('ip route show:\n')
    wrap_function_log_exception(lambda: sh.ip("route", "show", _out=output, _env=new_env))

    output.write('ip rule show:\n')
    wrap_function_log_exception(lambda: sh.ip("rule", "show", _out=output, _env=new_env))
    
    output.write('nft list ruleset:\n')
    wrap_function_log_exception(lambda: sh.nft("list", "ruleset", _out=output, _env=new_env))

    output.write('cat /etc/iproute2/rt_tables:\n')
    wrap_function_log_exception(lambda: sh.cat("/etc/iproute2/rt_tables", _out=output, _env=new_env))
    
    with open(network_info_path, 'w', encoding='utf-8') as writer:
        writer.write(output.getvalue())
    return {'network_info.txt': network_info_path}

@register_diagnostic_collection_func('Sysctl information', constants.LINUX_PLATFORM)
def collect_sysctl_info(args):
    output = io.StringIO()
    _, sysctl_info_path = tempfile.mkstemp(prefix=f'sysctl_info_{get_time_string()}', suffix='.txt')

    output.write('sysctl -a:\n')
    wrap_function_log_exception(lambda: sh.sysctl("-a", _out=output, _env=new_env))
    
    with open(sysctl_info_path, 'w', encoding='utf-8') as writer:
        writer.write(output.getvalue())
    return {'sysctl_info.txt': sysctl_info_path}


@register_diagnostic_collection_func('Hostname diagnostics information', constants.LINUX_PLATFORM)
def collect_hostname_diagnostics_information(args):
    output = io.StringIO()
    output.write("hostname:\n")
    sh.hostname(_out=output, _env=new_env)
    output.write("hostname -A:\n")
    sh.hostname("-A", _out=output, _env=new_env)
    output.write("dnsdomainname:\n")
    wrap_function_log_exception(lambda: sh.dnsdomainname(_out=output, _env=new_env))
    output.write("dnshostname:\n")
    wrap_function_log_exception(lambda: sh.dnshostname(_out=output, _env=new_env))
    output.write("domainname:\n")
    wrap_function_log_exception(lambda: sh.domainname("-A", _out=output, _env=new_env))
    output.write("cat /etc/hostname:\n")
    wrap_function_log_exception(lambda: sh.cat("/etc/hostname", _out=output, _env=new_env))
    output.write("cat /etc/resolv.conf:\n")
    wrap_function_log_exception(lambda: sh.cat("/etc/resolv.conf", _out=output, _env=new_env))
    output.write("cat /etc/hosts:\n")
    wrap_function_log_exception(lambda: sh.cat("/etc/hosts", _out=output, _env=new_env))
    output.write("cat /etc/nsswitch.conf:\n")
    wrap_function_log_exception(lambda: sh.cat("/etc/nsswitch.conf", _out=output, _env=new_env))
    output.write("getent:\n")
    wrap_function_log_exception(lambda: sh.getent("ahosts", sh.hostname().strip(), _out=output, _env=new_env))

    output.write("Collecting getaddrinfo information:\n")
    for info in socket.getaddrinfo(host=socket.gethostname(), port=None, family=socket.AF_INET,
                                  flags=socket.AI_CANONNAME):
        output.write("Entry: " + str(info) + "\n")
    _, hostname_diag_path = tempfile.mkstemp(prefix=f'hostname_diag_{get_time_string()}', suffix='.txt')
    with open(hostname_diag_path, 'w') as writer:
        writer.write(output.getvalue())
    return {'hostname_diagnostics.txt': hostname_diag_path}

@register_diagnostic_collection_func('MDE Event statistics', required_package='mdatp')
def collect_event_statistics(args):
    event_statistics = mdatp.collect_event_statistics()
    if not event_statistics:
        log.warn('Failed to collect MDE event statistics')
        return
    _, mde_event_statistics = tempfile.mkstemp(prefix=f'mde_event_statistics_{get_time_string()}', suffix='.txt')
    with open(mde_event_statistics, 'w') as writer:
        writer.write(event_statistics)
    return {'mde_event_statistics.txt' : mde_event_statistics}

@register_diagnostic_collection_func('MDE eBPF statistics(Linux platform)', constants.LINUX_PLATFORM, required_package='mdatp')
def collect_ebpf_statistics(args):
    ebpf_statistics = mdatp.collect_ebpf_statistics()
    if not ebpf_statistics:
        log.warn('Failed to collect MDE eBPF statistics')
        return
    _, mde_ebpf_statistics = tempfile.mkstemp(prefix=f'mde_ebpf_statistics_{get_time_string()}', suffix='.txt')
    with open(mde_ebpf_statistics, 'w') as writer:
        writer.write(ebpf_statistics)
    return {'mde_ebpf_statistics.txt' : mde_ebpf_statistics}

@register_diagnostic_collection_func('Kernel logs', constants.LINUX_PLATFORM)
def collect_kernel_logs(args):
    def file_lt_100MB(absolute_file_path):
        size = round(os.path.getsize(absolute_file_path)/(1024*1024),2) #Bytes to MB
        if size > 100:
            log.warn(f'Not collecting file [{absolute_file_path}] because of larger size [{size}] MB')
            return False
        return True

    kernel_logs_zip = tempfile.mkstemp(prefix=f'kernel_logs_{get_time_string()}', suffix='.zip')[1]

    create_zip(kernel_logs_zip, path='/var/log', prefix_pattern='kern.log', zipdir='kernel_logs', predicate=file_lt_100MB)

    return {'kernel_logs.zip' : kernel_logs_zip}

@register_diagnostic_collection_func('MDC logs', constants.LINUX_PLATFORM)
def collect_MDC_logs(args):
    all_mde_dirs = glob.glob(constants.MDC_CONFIG)
    if not all_mde_dirs:
        log.warn('MDE.Linux Extension folder doesn\'t exist. Going ahead as non-MDC')
        return

    latest_mde_dir = max(all_mde_dirs, key=os.path.getctime)
    latest_mde_config = os.path.join(latest_mde_dir, 'HandlerEnvironment.json')

    log_dir = json.load(open(latest_mde_config))[0]['handlerEnvironment']['logFolder']

    zip_created = False
    mdc_log_zip = tempfile.mkstemp(prefix=f'mdc_logs_{get_time_string()}', suffix='.zip')[1]
    if os.path.exists(log_dir):
        zip_created = create_zip(mdc_log_zip, path=log_dir, zipdir='mdc_logs/mde_logs')

    if zip_created:
        status_dir = os.path.join(latest_mde_dir, 'status')
        if os.path.exists(status_dir):
            create_zip(mdc_log_zip, path=status_dir, zipdir='mdc_logs/mdc_status', mode='a')
        else:
            log.warn(f'MDC status dir [{status_dir}] doesnt exist.')

        state_file = os.path.join(latest_mde_dir, 'state.json')
        if os.path.exists(state_file):
            create_zip(mdc_log_zip, files=[state_file], zipdir='mdc_logs', mode='a')
        else:
            log.warn(f'MDC state file [{state_file}] doesnt exist.')

    return {'mdc_log.zip' : mdc_log_zip}

@register_diagnostic_collection_func('Netext Config', constants.MACOS_PLATFORM, required_package='mdatp')
def collect_netext_config(args):
    netext_config = run_with_output(constants.NETEXT_CONFIG_FILE_PATH, timeout_in_sec=20)
    if not netext_config:
        log.warn("Failed to collect MDE netext_config")
        return
    _, netext_config_path = tempfile.mkstemp(prefix=f'mde_netext_config_{get_time_string()}', suffix='.txt')
    with open(netext_config_path, 'w') as writer:
        writer.write(netext_config)
    return {'netext_config.txt': netext_config_path}

class SystemMonitor():
    def __init__(self):
        time_str = get_time_string()
        _, self.out_file = tempfile.mkstemp(prefix=f'top_output_{time_str}', suffix='.txt')
        _, self.summary_file = tempfile.mkstemp(prefix=f'top_summary_{time_str}', suffix='.txt')
        _, self.outlier_file = tempfile.mkstemp(prefix=f'top_outlier_{time_str}', suffix='.txt')
        self.cpu_key = '%CPU'
        self.user_key = 'USER'
        self.pid_key = 'PID'
        if os_info.platform == constants.MACOS_PLATFORM:
            self.mem_key = 'MEM'
            self.command = ['top', '-l', '0', '-s', '5', '-o', self.mem_key]
            self.mem_converter = lambda x: str(self._bytes_to_mb(x)) + 'M'
        else:
            self.mem_key = '%MEM'
            self.command = ["top", "-b", '-d', '5', '-w', '512', '-o', self.mem_key]
            self.mem_converter = lambda x: x
        self.process = None

    def __enter__(self):

        #TODO Use the same logic at all the places where system call is made.
        if constants.IS_COMPILED_AS_BINARY and os_info.platform == constants.LINUX_PLATFORM:
            env = dict(os.environ)
            lp_key = 'LD_LIBRARY_PATH'
            lp_orig = env.get(lp_key + '_ORIG')

            if lp_orig is not None:
                env[lp_key] = lp_orig
            else:
                env.pop(lp_key, None)
            self.process = subprocess.Popen(self.command, stdout=open(self.out_file, 'w'), env=env)
        else:
            self.process = subprocess.Popen(self.command, stdout=open(self.out_file, 'w'))
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        if self.process:
            self.stop()

    def info(self):
        log.info(f'Top Command output: [{self.out_file}]')
        log.info(f'Top Command Summary: [{self.summary_file}]')
        log.info(f'Top Command Outliers: [{self.outlier_file}]')

    def monitor(self):
        run(self.command)

    def _to_bytes(self, size):
        if isinstance(size, int) or isinstance(size, float):
            return float(size)

        if size.endswith('+') or size.endswith('-'):
            return self._to_bytes(size[:-1])

        if size.endswith('B'):
            return float(size[:-1])
        if size.endswith('K'):
            return 1024*float(size[:-1])

        if size.endswith('M'):
            return self._to_bytes(str(1024*float(size[:-1]))+ 'K')
        if size.endswith('G'):
            return self._to_bytes(str(1024*float(size[:-1]))+ 'M')
        return float(size)

    def _bytes_to_mb(self, size):
        return round(size/(1024*1024), 2)

    def analyse_with_pandas(self, processed_data):
        import pandas as pd
        import numpy as np
        processed_data_df, outliers = self.remove_outliers(processed_data, pd, np)
        means_df = processed_data_df.groupby(['command', self.user_key, self.pid_key]).mean().reset_index().round(2)

        cpu_data_df = means_df.sort_values(self.cpu_key, ascending=False).head(10)
        cpu_data_df[self.mem_key] = cpu_data_df[self.mem_key].apply(self.mem_converter)
        cpu_data = cpu_data_df.to_csv(index=False)

        mem_data_df = means_df.sort_values(self.mem_key, ascending=False).head(10)
        mem_data_df[self.mem_key] = mem_data_df[self.mem_key].apply(self.mem_converter)
        mem_data = mem_data_df.to_csv(index=False)

        if command_exists('mdatp'):
            mdatp_processes = []
            mdatp_processes = mdatp.get_mdatp_processes()
            mdatp_pids = [x[0] for x in mdatp_processes]
            mdatp_owned_df = means_df.loc[means_df[self.pid_key].isin(mdatp_pids)].copy()
            mdatp_owned_df[self.mem_key] = mdatp_owned_df[self.mem_key].apply(self.mem_converter)
            for p in mdatp_processes:
                mdatp_owned_df['command'] = np.where(mdatp_owned_df[self.pid_key]==p[0], p[1], mdatp_owned_df['command'])

            cores_n = os.cpu_count()
            mdatp_owned_df[f'{self.cpu_key}/core'] = mdatp_owned_df.apply (lambda row: round(row[self.cpu_key]/cores_n, 4), axis=1)
            mdatp_owned = mdatp_owned_df.to_csv(index=False)
        else:
            mdatp_owned = "MDATP is not installed"

        outliers.to_csv(self.outlier_file, index=False)

        summary = "Top 10 CPU Consumer:\n\n" + cpu_data
        summary += '\n\n' + "*"*20 + "\n" + "Top 10 MEM Consumer:\n\n" + mem_data
        summary += '\n\n' + "*"*20 + "\n" + "MDATP owned process:\n\n" + mdatp_owned

        return summary

    def stop(self):
        try:
            self.process.kill()
            self.process.wait()

            raw_data = list(map(lambda x : re.sub(' +', ',', x.strip()),
                                open(self.out_file).readlines()))
            processed_data = self.process_data(raw_data)

            summary = ''

            try:
                summary = self.analyse_with_pandas(processed_data)
            except ModuleNotFoundError as ex:
                log.warn(f"Exception => {ex}. Outliers will not be removed and only basic data will be provided")
                #On MacOS, MEM is in absolute terms like B, KB, MB, GB
                #Whereas on Linux its in percentage
                processed_data.sort(key=lambda data: (self._to_bytes(data[self.mem_key]), self._to_bytes(data[self.cpu_key])), reverse = True)
                top_10_mem = self.get_top_n_unique(processed_data, 10)

                processed_data.sort(key=lambda data: (self._to_bytes(data[self.cpu_key]), self._to_bytes(data[self.mem_key])), reverse = True)
                top_10_cpu = self.get_top_n_unique(processed_data, 10)

                summary += "Top 10 CPU Consumer(may have outliers):\n\n" + pprint.pformat(top_10_cpu)
                summary += '\n\n' + "*"*20 + "\n" + "Top 10 MEM Consumer(may have outliers):\n\n" + pprint.pformat(top_10_mem)
            except Exception as ex:
                log.warn(f"Exception => {ex}")

            open(self.summary_file, "w").write(summary)

            self.process = None

            return {'top_output.txt': self.out_file,
                    'top_summary.txt':self.summary_file,
                    'top_outliers.txt':self.outlier_file}
        except Exception as e:
            log.error(f"Couldn't run analysis on top output. Exception => {e}")
            return {'top_output.txt': self.out_file}

    def get_top_n_unique(self, data, n):
        top_n_unique = list()
        added = set()
        i = 0
        while len(top_n_unique) < n and i<len(data):
            if data[i]['command'] not in added:
                top_n_unique.append(data[i])
                added.add(data[i]['command'])
            i+=1
        return top_n_unique

    def replaceOutliers(self, constant_df, pd, np):
        df = constant_df.copy(deep=True)
        IQR = df.quantile(0.75, numeric_only=True) - df.quantile(0.25, numeric_only=True)
        top_whisker = df.quantile(0.75, numeric_only=True) + 1.5*IQR
        low_whisker = df.quantile(0.25, numeric_only=True) - 1.5*IQR
        def replace_routine(df, whisker, op, reason):
            outliers = pd.DataFrame(columns=df.columns)
            for column, threshold in whisker.items():
                outliers = pd.concat([df[op(df[column], threshold)], outliers])
                outliers['outlier_type'] = reason
                df.loc[op(df[column], threshold), 'command'] = np.nan
                df.dropna(inplace=True)
            return outliers
        outliers = pd.concat([replace_routine(df, low_whisker, operator.lt, 'First quantile'), replace_routine(df, top_whisker, operator.gt, 'Fourth quantile')])
        return (df, outliers)

    def remove_outliers(self, data, pd, np):
        sorted_data = sorted(data, key=lambda x: (x['command'], x['PID']))

        grouped_by_process = itertools.groupby(sorted_data, key=lambda x: (x['command'], x['PID']))

        outliers = pd.DataFrame(columns=['command', self.pid_key, self.user_key, self.mem_key, self.cpu_key])
        processed_data =  outliers.copy()
        means = outliers.copy()
        for key, group in grouped_by_process:
            df = pd.DataFrame(list(group))
            #On MacOS, MEM is in absolute terms like B, KB, MB, GB
            df[self.mem_key] = df[self.mem_key].apply(self._to_bytes)
            df[[self.cpu_key, self.mem_key]] = df[[self.cpu_key, self.mem_key]].apply(pd.to_numeric)

            processed_df, outlier_df = self.replaceOutliers(df, pd, np)

            outliers = pd.concat([outliers, outlier_df])
            processed_data = pd.concat([processed_data, processed_df])

        outliers.reset_index()
        processed_data.reset_index()
        return (processed_data, outliers)
            

    def process_data(self, raw_data):
        header_tokens = []
        process_data = []

        cpu_index = 0
        mem_index = 0
        user_index = 0
        pid_index = 0
        command_index = (0,0)

        reading_data = False
        itr = iter(range(len(raw_data)))
        for i in itr:
            data = raw_data[i]
            if reading_data:
                if len(data) == 0: #[Linux] Checking new line to detect next top run
                    reading_data = False
                    continue
                tokens = data.split(',')
                if tokens[0] == 'Processes:': #[MacOS] No new line after the output, so checking the header token
                    reading_data = False
                    continue

                process_data.append({'command':' '.join(tokens[command_index[0]: command_index[1] + len(tokens) - len(header_tokens)]), #Command/process name may have spaces
                                     self.cpu_key: tokens[cpu_index + (0 if command_index[0] > cpu_index else len(tokens) - len(header_tokens))],
                                     self.mem_key: tokens[mem_index + (0 if command_index[0] > mem_index else len(tokens) - len(header_tokens))],
                                     self.user_key: tokens[user_index + (0 if command_index[0] > user_index else len(tokens) - len(header_tokens))],
                                     self.pid_key: tokens[pid_index + (0 if command_index[0] > pid_index else len(tokens) - len(header_tokens))].strip('*')})
            else:
                if len(data) == 0:
                    i = next(itr)
                    data = raw_data[i]
                    header_tokens = data.split(',')

                    cpu_index = header_tokens.index(self.cpu_key)
                    mem_index = header_tokens.index(self.mem_key)
                    user_index = header_tokens.index(self.user_key)
                    pid_index = header_tokens.index(self.pid_key)
                    command_index = (header_tokens.index('COMMAND'), header_tokens.index('COMMAND') + 1)

                    reading_data = True
        return process_data
