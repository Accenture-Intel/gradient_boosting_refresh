
from .utils import run, wait, run_with_output,error, command_exists
from .machine import machine, os_details
from collections import defaultdict
import logging
from . import constants
from . import filesystem as fs
import json, os, time, re
from os import path
from contextlib import contextmanager
import json
import shutil

log = logging.getLogger(constants.LOGGER_NAME)
os_info = os_details()

# -- Executables ----
PYTHON = 'python' # or python3
MDATP = "mdatp" #"/usr/local/bin/mdatp"

STANDARD_CLI = {
                "legacy" : False,
                "health" : "health",
                "health_features" : "health --details features",
                "health_json" : "health --output json",
                "health_field" : "health --field",
                "dlp_health" : "health --details data_loss_prevention",
                "health_permissions" : "health --details permissions",
                "diagnostics_create" : "diagnostic create",
                #"diagnostics_antivirus_engine_pool_content" : "diagnostic antivirus-engine-pool-content --time 10 --output json", #enable back once --time 10 get released to prod
                "diagnostics_rtp_statistics" : "diagnostic real-time-protection-statistics --sort --list-all",
                "set_edr_early_preview" : "edr early-preview",
                "early_preview_cmd_success" : "Early preview changed",
                "get_edr_early_preview" : "health --field edr_early_preview_enabled",
                "connectivity_test" : "connectivity test",
                "app_version" : "app_version",
                "edr_group_ids" : "edr group-ids --group-id",
                "edr_group_ids_cmd_success" : "Group id configured",
                "edr_set_tag" : "edr tag set --name GROUP --value",
                "edr_remove_tag": "edr tag remove --tag-name GROUP",
                "edr_get_tag" : "health --field edr_device_tags",
                "config_set_rtp" : "config real-time-protection --value",
                "exclusion_get_list" : "exclusion list",
                "exclusion_folder" : "exclusion folder",
                "definitions_status" : "definitions_status",
                "definitions_details" : "health --details definitions",
                "definitions_details_json" : "health --details definitions --output json",
                "update_definitions" : "definitions update",
                "updated" : "up_to_date",
                "org_id" : "org_id",
                "group_ids" : "edr_group_ids",
                "configuration" : "edr_configuration_version",
                "machine_id" : "edr_machine_id",
                "managed_by" : "managed_by",
                "release_ring" : "release_ring",
                "real_time_protection_enabled" : "real_time_protection_enabled",
                "log_level" : "log level set --level",
                "log_rotate": "config log-rotation-parameters",
                "event_statistics" : "diagnostic event-provider-statistics",
                "unenroll_from_mde_attach" : "unenroll_from_mde_attach",
                "hot_event_sources" : "diagnostic hot-event-sources",
                "ebpf_statistics" : "diagnostic ebpf-statistics",
                True : "enable",
                False : "disable"
               }


LEGACY_CLI = {
                "legacy" : True,
                "health" : "--health",
                "health_json" : "health --output json",
                "health_field" : "--health",
                "diagnostics_create" : "--diagnostic --create",
                "set_edr_early_preview" : "--edr --early-preview",
                "early_preview_cmd_success" : "Configuration updated successfully",
                "get_edr_early_preview" : "--health edrEarlyPreviewEnabled",
                "connectivity_test" : "--connectivity-test",
                "app_version" : "appVersion",
                "edr_group_ids" : "--edr --groupids",
                "edr_group_ids_cmd_success" : "Configuration updated successfully",
                "edr_set_tag" : "--edr --set-tag GROUP",
                "edr_get_tag" : "--health edrDeviceTags",
                "config_set_rtp": "--config realTimeProtectionEnabled",
                "exclusion_folder" : "--exclusion --add-folder",
                "definitions_status" : "definitionsStatus",
                "definitions_details" : "definitionsStatus",
                "definitions_details_json" : "definitionsStatus --output json",
                "update_definitions" : "--definition-update",
                "updated" : "upToDate",
                "org_id" : "orgId",
                "machine_id" : "edrMachineId",
                "real_time_protection_enabled" : "realTimeProtectionEnabled",
                True : "on",
                False : "off" 
             }


class mdatp:

    cli = STANDARD_CLI
    boots = 0
    platform = machine.get_platform()

    @staticmethod
    def allow_sys_ext():
        if mdatp.platform != constants.MACOS_PLATFORM:
            log.info('Linux machine - system extension is not required')
            return True
        os_version = run_with_output('sw_vers -productVersion')
        macOS_version = re.findall(r"(\d+\.\d+).*",os_version)[0]
        log.info("macOS_version: "+str(macOS_version)) ## trying to figure out if the version number has 4/5 digits (for example 11.6 or 10.13)
        if not float(macOS_version) >= 10.15:
            log.info('old macOS version - system extension is not required')
            return True
        run('sudo chmod +x ../../common/setup_system_extensions.sh')
        return run('sudo ../../common/setup_system_extensions.sh')
     


    @staticmethod
    def _remove_unnecessary_blobs(is_geo_test = False):
        onboarding_file_path = mdatp._get_unnecessary_blobs_path()
        command = f"cd " + onboarding_file_path
        if mdatp.platform == constants.MACOS_PLATFORM:
            command = command + " && sudo rm ./*.plist"
            if is_geo_test:
                command = command + " && sudo rm wdavcfg wdavhistory wdavstate"
        if mdatp.platform == constants.LINUX_PLATFORM:
            command = command + " && sudo rm ./*.json"
            if is_geo_test:
                command = command + " && sudo rm wdavcfg wdavhistory wdavstate"
        run(command)


    @staticmethod
    def switch_cli(legacy=True):
        mdatp.cli = LEGACY_CLI if legacy else STANDARD_CLI

    @staticmethod
    def _get_unnecessary_blobs_path():
        if mdatp.platform == constants.MACOS_PLATFORM:
            return f"/Library/Application\\ Support/Microsoft/Defender/"
        elif mdatp.platform == constants.LINUX_PLATFORM:
            return f"/etc/opt/microsoft/mdatp/"
        else:
            raise Exception("Unsupported platform")

    @staticmethod
    def _get_uninstall_command():
        platform = machine.get_platform()
        #TODO create a login to uninstall on Linux machines
        if platform == constants.MACOS_PLATFORM:
            return "sudo rm -rf {0}"
        else:
            raise Exception("Unsupported platform")

    @staticmethod
    def uninstall_agent(package_path = ''):
        platform = machine.get_platform()
        #TODO create a login to uninstall on Linux machines
        if platform == constants.MACOS_PLATFORM:
            if os.path.isdir('/Applications/Microsoft Defender.app/'):
                package_path = '/Applications/Microsoft\ Defender.app/'
            elif os.path.isdir('/Applications/Microsoft Defender ATP.app/'):
                package_path = '/Applications/Microsoft\ Defender ATP.app/'
            if package_path == '':
                log.info("package path is empty when uninstall agent")
                return False
        uninstall_command = mdatp._get_uninstall_command().format(package_path)
        return run(uninstall_command) and mdatp._uninstall_background_validation()

    @staticmethod
    def _uninstall_background_validation(timeout = 60):
        start_time = time.time()
        while time.time() - start_time < timeout:
            if os.popen('ps aux|grep Defender/uninstall/uninstall |grep -v grep').read():
                print(">> Uninstall Step 1: Found uninstall background process")
                start_time = time.time()
                while time.time() - start_time < timeout:
                    if os.popen('ps aux|grep Defender/uninstall/uninstall |grep -v grep').read():
                        print(">> Uninstall Step 2: Validate uninstall process is finished")
                        return True            
        return False

    @staticmethod
    def _get_state():
        wdavstate_path = constants.WDAV_STATE[mdatp.platform]
        try:
            if os.path.exists(wdavstate_path):
                f = open(wdavstate_path, 'r')
                return json.load(f)
            else:
                return None
        except ValueError:
            log.error('Could not load configuration file')
            return None

    @staticmethod
    def kill_all_mdatp_processes(attempts = 6):
        command = "sudo killall -9 wdavdaemon "
        if mdatp.platform == constants.MACOS_PLATFORM:
            command = command + "telemetryd_v1 telemetryd_v2"
        else:
            command = command + "telemetryd_v2"
        run(command)

        while not mdatp.is_healthy() and attempts > 0:
            wait(5, "waiting for agent to start")
            attempts = attempts - 1
        mdatp.boots = mdatp.boots + 1

    @staticmethod
    def reset(timeout = 60, audit_logging = True):
        start_time = time.time()
        log.info("restarting MDE service")

        mdatp._turn_off()
        wait(5, "shutting down...")

        mdatp._turn_on()
        wait(5, "turning on...")

        while not mdatp.is_healthy() and time.time() - start_time < timeout:
            wait(5, "waiting for agent to start")

        if not mdatp.is_healthy():
            log.warning("agent had not recovered")
        mdatp.boots = mdatp.boots + 1

        if machine.get_platform() == "Linux":
            wait(30, "waiting for auditd to stabilize")
            if audit_logging:
                log.info(f"auditd status:\n{mdatp.auditd_status()}")
                log.info(f"auditd rules:\n{mdatp.auditd_loaded_rules()}")


    @staticmethod
    def _turn_off():
        if machine.get_platform() == constants.MACOS_PLATFORM:
            command = 'sudo launchctl unload /Library/LaunchDaemons/com.microsoft.fresno.plist'
        else:
            command = 'sudo systemctl stop mdatp'
        run(command)

    @staticmethod
    def _turn_on():
        if machine.get_platform() == constants.MACOS_PLATFORM:
            command = 'sudo launchctl load /Library/LaunchDaemons/com.microsoft.fresno.plist'
        else:
            command = 'sudo systemctl start mdatp'
        run(command)

    @staticmethod
    def restart_auditd():
        command = 'sudo service auditd restart'
        run(command)
        
        start_time = time.time()
        while (not mdatp.auditd_status(full=False) == 'active (running)') and (time.time() - start_time < 60):
            wait(5, "waiting for auditd to start")
        
        if not mdatp.auditd_status(full=False) == 'active (running)':
            log.warning("auditd had not recovered")
            return False
        
        return True

    @staticmethod
    def auditd_status(full=True):
        command = 'sudo service auditd status'
        output = run_with_output(command)
        if full:
            return output
        matches = re.findall(r'Active:\s+(.+?) since', output)
        return matches[0] if matches else None
    
    @staticmethod
    def auditctl_status():
        command = 'sudo auditctl -s'
        output = run_with_output(command)
        return '\n'.join([command, '=' * len(command), output]);
    
    @staticmethod
    def auditd_conf():
        command = 'sudo cat /etc/audit/auditd.conf'
        output = run_with_output(command)
        return '\n'.join([command, '=' * len(command), output]);

    @staticmethod
    def audispd_conf():
        if not os.path.exists("/etc/audisp/audispd.conf"):
            return ''
        command = 'sudo cat /etc/audisp/audispd.conf'
        output = run_with_output(command)
        return '\n'.join([command, '=' * len(command), output]);

    @staticmethod
    def auditd_syslog():
        output = ''        
        if os.path.exists("/var/log/syslog"):
            command = 'sudo cat /var/log/syslog'
            command_output = run_with_output(command)
            output = '\n'.join([command, '=' * len(command), command_output])
        if os.path.exists("/var/log/messages"):
            command2 = 'sudo cat /var/log/messages'
            command_output2 = run_with_output(command2)
            output = '\n'.join([output, '\n', command2, '=' * len(command2), command_output2])
        return output

    @staticmethod
    def auditd_version():
        command = 'sudo auditctl -v'
        output = run_with_output(command)
        return '\n'.join([command, '=' * len(command), output]);

    @staticmethod
    def auditd_loaded_rules():
        command = 'sudo auditctl -l'
        output = run_with_output(command)
        return '\n'.join([command, '=' * len(command), output]);
    
    @staticmethod
    def auditd_deployed_rules():
        command = 'sudo find /etc/audit/rules.d/ -name "*.rules" -exec ls {} \; -exec echo "================================" \; -exec sudo cat {} \; -exec echo "================================" \;'
        if os.path.exists('/etc/audit/rules.d/'):
            output = run_with_output(command)
        else:
            output = '/etc/audit/rules.d/ doesnt exist'
        return '\n'.join([command, '=' * len(command), output]);

    @staticmethod
    def auditd_deployed_plugins():
        command = 'sudo find /etc/audit/plugins.d/ -name "*.conf" -exec ls {} \; -exec echo "================================" \; -exec sudo cat {} \; -exec echo "================================" \;'
        if os.path.exists('/etc/audit/plugins.d/'):
            output = run_with_output(command)
        else:
            output = '/etc/audit/plugins.d/ doesnt exist'
        return '\n'.join([command, '=' * len(command), output]);

    @staticmethod
    def audisp_deployed_rules():
        command = 'sudo find /etc/audisp/rules.d/ -name "*.rules" -exec ls {} \; -exec echo "================================" \; -exec sudo cat {} \; -exec echo "================================" \;'
        if os.path.exists('/etc/audisp/rules.d/'):
            output = run_with_output(command)
        else:
            output = '/etc/audisp/rules.d/ doesnt exist'
        return '\n'.join([command, '=' * len(command), output]);

    @staticmethod
    def audisp_deployed_plugins():
        command = 'sudo find /etc/audisp/plugins.d/ -name "*.conf" -exec ls {} \; -exec echo "================================" \; -exec sudo cat {} \; -exec echo "================================" \;'
        if os.path.exists('/etc/audisp/plugins.d/'):
            output = run_with_output(command)
        else:
            output = '/etc/audisp/plugins.d/ doesnt exist'
        return '\n'.join([command, '=' * len(command), output]);

    @staticmethod
    def is_alive():
        return run(f"{MDATP} {mdatp.cli['health']} > /dev/null")  # health connects to edr and av daemons

    @staticmethod
    def is_onboarded():
        org_id = mdatp.get_org_id()
        if org_id is None or org_id == '' or org_id == 'null' or 'unavailable' in org_id:
            return False
        return True

    @staticmethod
    def _get_install_command():
        if mdatp.platform == constants.MACOS_PLATFORM:
            return "sudo installer -pkg {0} -target /"
        elif mdatp.platform == constants.LINUX_PLATFORM:
            return f"sudo {machine.package_manager} install -y " + "{0}"
        else:
            raise Exception("Unsupported platform")        
    
    @staticmethod
    def install_agent(package_path):
        install_command = mdatp._get_install_command().format(package_path)
        success = run(install_command)
        if not success:
            return False

        mdatp.boots = mdatp.boots + 1
        attempts = 4
        while not mdatp.is_alive() and attempts > 0:
            wait(5, "waiting for agent to start")
            attempts = attempts - 1

        return mdatp.is_alive()

    @staticmethod
    def find_script_type(script_name):
        type = script_name.split(".")[-1].strip()
        log.info(f"script type is {type}")
        return 'bash' if type == 'sh' else 'python' if type == 'py' else ''

    @staticmethod
    def onboard(script_name):
        if script_name is None or script_name == '':
            return False
        if not mdatp.is_alive():
            log.warning("can't onboard. mde is not running")
            return False
        mdatp._remove_unnecessary_blobs()
        script_manager = mdatp.find_script_type(script_name)
        log.info(f"going to run onboarding via {script_manager}")
        result = run(f"sudo {script_manager} {os.path.join(machine.get_download_folder(), script_name)}")
        wait(6, "let onboarding script work")
        mdatp.reset()
        return result

    @staticmethod
    def unenroll_from_mde_attach():
        platform = machine.get_platform()
        if platform == constants.LINUX_PLATFORM:
            raise Exception("Unsupported platform")
        if not mdatp.is_alive():
            log.warning("can't unenroll mde is not running")
            return False
        if mdatp._get_health_parameter(mdatp.cli['managed_by']) != "MDE":
            log.warning("Cannot unenroll the device from mde-attach, as the device is not enrolled")
            return False
        log.info("going to unenroll the device from mde attach")
        return run(f"sudo {MDATP} {mdatp.cli['unenroll_from_mde_attach']}")

    @staticmethod
    def dev_geo_onboard(api,timeout=60):
        ## TODO: create an API calls to download scripts
        log.debug("Api geo: "+api.geo)
        if not api.onboard():
            return error("dev geo onboard was failed")
        return True

    @staticmethod
    def dev_geo_offboard(geo):
        log.info("dev geo offboarding start")
        if not mdatp.is_onboarded():
            log.info("machine is not onboarded")
            return True

        if not machine.get_platform() == constants.MACOS_PLATFORM:
            command = f"sudo {PYTHON} ./SetupScripts/{geo.upper()}OffboardingLinuxServer_valid_until_2061-05-21.py"
        else:
            command = f"sudo {PYTHON} ./SetupScripts/{geo.upper()}OffboardingMacOs_valid_until_2061-05-21.py"

        success = run(command)
        wait(10, "wait for offboarding complete")

        if not success:
            return False
        return True

    @staticmethod
    def dev_onboard(timeout=10):
        if mdatp.is_onboarded():
            return True
        
        start_time = time.time()
        success = run("../../../src/install/create_dev_license.sh")
        
        if not success:
            return False
        
        while time.time() - start_time < timeout and not mdatp.is_onboarded():
            wait(1, 'waiting for onboaring to complete')
        
        return mdatp.is_onboarded()
    
    @staticmethod
    def offboard(script_name):
        if script_name is None or script_name == '':
            log.info("offboarding script is missing")
            return False
        if not mdatp.is_onboarded():
            log.info("the product is not onboarded")
            return True
        log.debug("script name: "+ script_name)
        mdatp._remove_unnecessary_blobs()
        script_manager = mdatp.find_script_type(script_name)
        log.info(f"going to run offboarding via {script_manager}")
        if run(f"sudo {script_manager} {os.path.join(machine.get_download_folder(), script_name)}"):
            wait(5, "let offboarding script work")
            return True
        return False

    @staticmethod
    def update_definitions():
        if mdatp.is_healthy():
            return True
        log.info("updating definitions...")
        start_time = time.time()
        success = run(f"sudo {MDATP} {mdatp.cli['update_definitions']}")
        elapsed_time = time.time()-start_time

        if not success:
            log.info("update failed [{elapsed_time:.2f}sec]")
            return False
        
        log.info(f"updated: [{elapsed_time:.2f}sec]")
        end_time = time.time() + 30
        while time.time() < end_time:
            if mdatp.is_healthy():
                return True
            wait(3,"wait for health status to update")
        log.info("update failed")
        return False

    @staticmethod
    def collect_logs(copy_to_collection=True):
        if not mdatp.is_alive():
            log.warning("mde is not running")
        output = run_with_output(f"sudo {MDATP} {mdatp.cli['diagnostics_create']}", timeout_in_sec=20)
        if output is None:
            log.warn("diagnostic create empty output")
            return
        
        collected_logs = output.split('"')[1]
        
        wait(3, "waiting for agent to create diagnostic package")
        log.info("diagnostic package path: " + collected_logs)

        if copy_to_collection and not machine.copy_to_collection_folder(collected_logs):
            log.warning("failed to copy diagnostic package")
            return None

        return collected_logs
    
    # @staticmethod
    # def collect_engine_pool_content(legacy = False, as_json=True):
    #     if not mdatp.is_alive():
    #         return None

    #     return run_with_output(f"sudo {MDATP} {mdatp.cli['diagnostics_antivirus_engine_pool_content']}", timeout_in_sec=20)

    @staticmethod
    def collect_cache():
        if not mdatp.is_alive():
            return None

        if not mdatp.platform == constants.MACOS_PLATFORM:
            return None

        cache_dir = '/var/root/Library/Caches/CLL/P-WDATP/'
        collected_package = '/tmp/cll_logs.zip'
        success = run(f"sudo zip /tmp/cll_logs.zip {cache_dir}")
        log.info(f"success: [{success}]")
        if not success:
            log.warning("warning, unable to collect cache")
            return False
        log.info(f"collected cache files: {collected_package}")

        if not machine.copy_to_collection_folder(collected_package):
            log.warning("warning, unable to collect cache")
            return False

        return True


    @staticmethod
    def collect_crash_logs(keys, copy_to_collection=True, check_file_size=True):
        log.info(" collecting crash dumps")
        crash_logs = []
        crash_file_path = machine.get_crash_dump_dir()
        start_time = machine.get_start_time()
        if not os.path.isdir(crash_file_path):
            log.info(f"{crash_file_path} crash dumps directory does not exists")
            return
        for filename in os.listdir(crash_file_path):
            if not [key for key in keys if (key in filename)]:
                continue
            file_create_time = os.path.getmtime(os.path.join(crash_file_path, filename))
            if mdatp.platform == constants.LINUX_PLATFORM:
                if file_create_time > start_time:
                    crash_logs.append(os.path.join(crash_file_path, filename))
            elif mdatp.platform == constants.MACOS_PLATFORM:
                crash_logs.append(os.path.join(crash_file_path, filename))
        
        total_size = 0
        max_count = 20
        

        if mdatp.platform == constants.LINUX_PLATFORM:
            # Collect crashes processed by crashpad. These files do not have wdavdaemon in the name.
            crash_file_path_root = '/var/opt/microsoft/mdatp/crash'
            crash_file_path_suffixes = ['new', 'pending', 'completed']
            count = 0
            max_size = 1024 * 1024 * 500 # 500MB

            for suffix in crash_file_path_suffixes:
                crash_subdir = os.path.join(crash_file_path_root, suffix)
                if not os.path.exists(crash_subdir):
                    continue
                # Crash files are root protected
                files = str(run_with_output(f"sudo ls {crash_subdir}")).split()
                for filename in files:
                    if '.dmp' in filename:
                        full_path = os.path.join(crash_subdir, filename)
                        if check_file_size:
                            total_size = total_size + os.path.getsize(str(full_path))
                        if total_size > max_size or count > max_count:
                            # Don't collect GBs worth of crashes. 500MB or 20 files is plenty.
                            break
                        crash_logs.append(full_path)
                        count = count + 1
        elif mdatp.platform == constants.MACOS_PLATFORM:
            max_size = 1024 * 1024 * 30 # 30MB
            crash_logs.sort(key=os.path.getmtime, reverse=True)
            if len(crash_logs) > max_count:
                crash_logs = crash_logs[:max_count]
            if len(crash_logs) > 0:
                total_size = total_size + os.path.getsize(str(crash_logs[0]))
            for i in range(1, len(crash_logs)):
                if check_file_size:
                    total_size = total_size + os.path.getsize(str(crash_logs[i]))
                if total_size > max_size:
                    crash_logs = crash_logs[:i]
                    break

        if len(crash_logs) == 0:
            return

        if copy_to_collection:
            for crash_log in crash_logs:
                if not machine.change_permissions(crash_log):
                    log.info(f"Warning: could not change permissions for {crash_log}")
                if not machine.copy_to_collection_folder(crash_log):
                    log.info(f"Warning: could not copy {crash_log} to collection folder")
        return crash_logs

    @staticmethod
    def get_machine_id():
        machine_id = mdatp._get_health_parameter(mdatp.cli['machine_id'])
        attempts = 0
        while not machine_id and attempts < 5:
            machine_id = mdatp._get_health_parameter(mdatp.cli['machine_id'])
            time.sleep(0.5)
            attempts = attempts + 1
            log.info("trying to get machine id: [{0}] attempts: [{1}<<5]".format(machine_id, attempts))
        return machine_id

    @staticmethod
    def get_rtp():  
        return mdatp._get_health_parameter(mdatp.cli['real_time_protection_enabled'])

    @staticmethod
    def get_org_id():
        return mdatp._get_health_parameter(mdatp.cli["org_id"])

    @staticmethod
    def get_release_ring():
        return mdatp._get_health_parameter(mdatp.cli["release_ring"])

    @staticmethod
    def is_healthy():
        return str(mdatp._get_health_parameter("healthy")) in ["1", "true", True]
    
    @staticmethod
    def set_early_preview(on = True):
        return run(f"sudo {MDATP} {mdatp.cli['set_edr_early_preview']} {mdatp.cli[on]}", verbose=True)

    @staticmethod
    def get_early_preview():
        return run_with_output(f"{MDATP} {mdatp.cli['get_edr_early_preview']}").replace('"','')

    @staticmethod
    def run_connectivity_test(timeout_sec=45):
        return run_with_output(f"{MDATP} {mdatp.cli['connectivity_test']}", timeout_in_sec=timeout_sec, return_stdout_on_err=True)

    @staticmethod
    def get_version():
        return mdatp._get_health_parameter(mdatp.cli['app_version'])

    @staticmethod
    def apply_groupid(groupid):
        if not mdatp.is_alive():
            return False
        response = run_with_output(f"sudo {MDATP} {mdatp.cli['edr_group_ids']} \"{groupid}\"")
        log.info(f"response={response}")
        return response == mdatp.cli["edr_group_ids_cmd_success"]

    @staticmethod
    def apply_tag(tag):
        if not mdatp.is_alive():
            return False
        response = run_with_output(f"sudo {MDATP} {mdatp.cli['edr_set_tag']} \"{tag}\"")
        return response == "Configuration updated successfully"

    @staticmethod
    def remove_tag():
        if not mdatp.is_alive():
            return False
        response = run_with_output(f"sudo {MDATP} {mdatp.cli['edr_remove_tag']}")
        return response == "Configuration updated successfully"

    @staticmethod
    def get_tags():
        return run_with_output(f"sudo {MDATP} {mdatp.cli['edr_get_tag']}")

    @staticmethod
    def set_rtp(status):
        if not mdatp.is_alive():
            return False
        response = run_with_output(f"sudo {MDATP} {mdatp.cli['config_set_rtp']} {status}")
        return response == "Configuration property updated"

    @staticmethod
    def get_exclusions():
        return run_with_output(f"sudo {MDATP} {mdatp.cli['exclusion_get_list']}")

    @staticmethod
    def folder_exclusion(method,path): ## Method add or remove
        if not mdatp.is_alive():
            return False
        print(f"sudo {MDATP} {mdatp.cli['exclusion_folder']} {method} --path {path}")
        response = run_with_output(f"sudo {MDATP} {mdatp.cli['exclusion_folder']} {method} --path {path}")
        return response == "Folder exclusion configured successfully"

    @staticmethod
    def get_group_id():
        if mdatp.cli['legacy']:
             return None
        return mdatp._get_health_parameter(mdatp.cli['group_ids'])

    @staticmethod
    def get_configuration():
        if mdatp.cli['legacy']:
             return None
        return mdatp._get_health_parameter(mdatp.cli['configuration'])

    @staticmethod
    def health_data(legacy = False, as_json=False):
        if not mdatp.is_alive():
            return None
        return run_with_output(f"{MDATP} {mdatp.cli['health_json' if as_json else 'health']}", return_stdout_on_err=True)

    @staticmethod
    def health_features_data(legacy = False, as_json=False):
        if not mdatp.is_alive():
            return None
        return run_with_output(f"{MDATP} {mdatp.cli['health_features']}", return_stdout_on_err=True)

    @staticmethod
    def dlp_health_data(legacy = False):
        if not mdatp.is_alive():
            return None
        return run_with_output(f"{MDATP} {mdatp.cli['dlp_health']}", return_stdout_on_err=True)

    @staticmethod
    def health_permissions_data(legacy = False, as_json=False):
        if not mdatp.is_alive():
            return None
        return run_with_output(f"{MDATP} {mdatp.cli['health_permissions']}", return_stdout_on_err=True)

    @staticmethod
    def definitions_data(legacy=False, as_json=False):
        if not mdatp.is_alive():
            return None
        return run_with_output(f"{MDATP} {mdatp.cli['definitions_details' if as_json else 'definitions_details_json']}", return_stdout_on_err=True)

    @staticmethod
    def processes_data():
        search_key = "(mdatp)|(auditd)" if mdatp.platform == "Linux" else "(wdav)"
        return run_with_output(f"sh -c 'ps aux | grep -E \"{search_key}|(COMMAND)\"'")

    @staticmethod
    def rtp_statistics():
        if not mdatp.is_alive() or mdatp.cli['legacy']:
            return None
        return run_with_output(f"{MDATP} {mdatp.cli['diagnostics_rtp_statistics']}")

    @staticmethod
    def get_v1_database_root():  
        state = mdatp._get_state()
        if state:
            return state['engineCore']['databaseRootPath']
        return None

    @staticmethod
    def get_database_root():  
        state = mdatp._get_state()
        if state:
            if 'v2EngineCore' in state: # Legacy
                return state['v2EngineCore']['databaseRootPath']
            else:
                return state['engineCore']['databaseRootPath']
        return None

    @staticmethod
    def get_edr_identity():  
        state = mdatp._get_state()
        try:
            if state:
                return state['edr']['identity']
        except:
            pass

        return None

    @staticmethod
    def get_mde_directories():
        if mdatp.platform == constants.MACOS_PLATFORM:
            app_path = ''
            if os.path.isdir('/Applications/Microsoft Defender ATP.app'):
                app_path = '/Applications/Microsoft Defender ATP.app'
            elif os.path.isdir('/Applications/Microsoft Defender.app'):
                app_path = '/Applications/Microsoft Defender.app'
            paths = [
                '/Library/Application Support/Microsoft/Defender',
                app_path,
                '/Library/Managed Preferences',
                '/Library/Extensions/wdavkext.kext']
        else:
            paths = [
                '/opt/microsoft/mdatp',
                '/var/opt/microsoft/mdatp',
                '/var/log/microsoft/mdatp',
                '/etc/opt/microsoft/mdatp']
        v1_database = mdatp.get_v1_database_root()
        if v1_database:
            paths.append(v1_database)
        v2_database = mdatp.get_database_root()
        if v2_database:
            paths.append(v2_database)
        return paths

    @staticmethod
    def _get_health_parameter(parameter):
        if not mdatp.is_alive():
            return None
        result = run_with_output(f"{MDATP} {mdatp.cli['health_field']} {parameter}")
        if result is None:
            return None
        # Take last line since if product is unlicensed the first list would be "ATTENTION: No license found"
        return result.replace('"','').split('\n')[-1]

    @staticmethod
    def get_mdatp_processes():
        processes = []
        if mdatp.platform == constants.LINUX_PLATFORM:
            processes_output = run_with_output("sh -c 'ps -A -o pid,command | grep mdatp | grep -v grep'")
        elif mdatp.platform == constants.MACOS_PLATFORM:
            processes_output = run_with_output("sh -c 'ps -A -o pid,command | grep wdav | grep -v grep'")
        for process in processes_output.split('\n'):
            process = process.strip()
            pid, command = process.split(' ', 1)
            command = command.strip()
            processes.append((pid, command))

        return processes

    @staticmethod
    def check_mdatp_processes_status():
        processes_status = defaultdict(int)
        processes = mdatp.get_mdatp_processes()
        if len(processes) == 0:
            return processes_status

        for process in processes:
            pid, command = process
            if ' edr' in command:
                processes_status['edr'] += 1
            elif 'wdavdaemon unprivileged' in command:
                processes_status['unprivileged'] += 1
            elif 'telemetryd_v2' in command:
                processes_status['telemetryd_v2'] += 1
            elif 'telemetryd_v1' in command:
                processes_status['telemetryd_v1'] += 1
            elif 'audisp_plugin' in command:
                processes_status['audisp'] += 1
            elif 'crashpad_handler' in command:
                processes_status['crashpad'] += 1
            elif 'com.microsoft.wdav.epsext' in command:
                processes_status['epsext'] += 1
            elif command.endswith('wdavdaemon') or command.endswith('wdavdaemon privileged'):
                processes_status['av'] += 1
        return processes_status

    @staticmethod
    def vmmap_wdavdaemon_processes(temp_dir):
        # vmmap wdavdaemon processes
        if mdatp.platform == constants.MACOS_PLATFORM:
            run_with_output("sh -c 'pgrep wdavdaemon_enterprise | xargs -I replstr /usr/bin/vmmap replstr -submap > %s'" % path.join(temp_dir, "wdavdaemon_enterprise_vmmap.txt"), timeout_in_sec=60)
            run_with_output("sh -c 'pgrep telemetryd | xargs -I replstr /usr/bin/vmmap replstr -submap > %s'" % path.join(temp_dir, "telemetryd_vmmap.txt"), timeout_in_sec=60)
            run_with_output("sh -c 'pgrep wdavdaemon_unprevilged | xargs -I replstr /usr/bin/vmmap replstr -submap > %s'" % path.join(temp_dir, "wdavdaemon_unprevilged_vmmap.txt"), timeout_in_sec=60)

    @staticmethod
    def sample_edr_processes(temp_dir):     
        # Sample only EDR processes to avoid deadlock
        if mdatp.platform == constants.MACOS_PLATFORM:
            run_with_output("sh -c 'pgrep telemetryd wdavdaemon_enterprise | xargs -I replstr /usr/bin/sample replstr -mayDie -f %s'" % path.join(temp_dir, "replstr_sample.txt"), timeout_in_sec=60)

    @staticmethod
    def set_log_level(log_level):
        return run_with_output(f"{MDATP} {mdatp.cli['log_level']} {log_level}")

    @staticmethod
    def _get_log_rotation_params():
        params = json.loads('{"maxCurrentSize":"5242880","maxRotatedSize":"15728640"}')
        cfg_path = constants.WDAV_CFG[mdatp.platform]
        
        try:
            if os.path.exists(cfg_path):
                wdav_cfg = json.load(open(cfg_path))            
                params = wdav_cfg['logRotationParameters'] #as Bytes
        except ValueError:
            log.error('wdav_cfg file is not found')
        except KeyError:
            log.error('wdav_cfg does not contain key logRotationParameters (old format likely)')

        return dict((key, int(val)//1048576) if val else (key, val) for key, val in params.items()) #Bytes to MegaBytes(MB)

    @staticmethod
    def set_log_rotation_params(maxCurrentSize=None, maxRotatedSize=None):
        if maxCurrentSize:
           run_with_output(f"{MDATP} {mdatp.cli['log_rotate']} max-current-size --size {maxCurrentSize}")

        if maxRotatedSize:
           run_with_output(f"{MDATP} {mdatp.cli['log_rotate']} max-rotated-size --size {maxRotatedSize}")

        if maxCurrentSize or maxRotatedSize:
            mdatp.reset(audit_logging=False)

    @staticmethod
    def collect_event_statistics():
        return run_with_output(f"{MDATP} {mdatp.cli['event_statistics']}")

    @staticmethod
    def collect_ebpf_statistics(monitor_time_in_sec=20, timeout_in_sec=60):
        return run_with_output(f"{MDATP} {mdatp.cli['ebpf_statistics']} --time {monitor_time_in_sec}", timeout_in_sec)

    class LogManager():
        def __init__(self, log_level, max_log_size):
            self.mdatp_installed = command_exists('mdatp')
            if not self.mdatp_installed:
                return

            self.default_log_level = mdatp._get_health_parameter('log_level')
            self.log_level = log_level

            if max_log_size:
                self.default_log_rotate_params = mdatp._get_log_rotation_params()

                if max_log_size < self.default_log_rotate_params['maxCurrentSize']:
                    raise ValueError(f"Passed max log size[{max_log_size} MB] is less than existing limit[{self.default_log_rotate_params['maxCurrentSize']} MB]")
                elif max_log_size == self.default_log_rotate_params['maxCurrentSize']:
                    log.info(f"Passed max log size[{max_log_size} MB] is same as existing limit. No change will be made")
                else:
                    self.expanded_log_rotate_params = dict()
                    self.expanded_log_rotate_params['maxCurrentSize'] = max_log_size
                    if max_log_size > self.default_log_rotate_params['maxRotatedSize']:
                        self.expanded_log_rotate_params['maxRotatedSize'] = max_log_size
                    else:
                        del self.default_log_rotate_params['maxRotatedSize']

        def __enter__(self):
            if self.mdatp_installed and mdatp.is_alive():
                if self.log_level and self.default_log_level != self.log_level:
                    log.info(f'Setting log level to [{self.log_level}]')
                    mdatp.set_log_level(self.log_level)

                if hasattr(self, 'expanded_log_rotate_params'):
                    log.info(f'Setting mdatp log rotate params to [{({key:str(val)+"MB" for key, val in self.expanded_log_rotate_params.items()})}]')
                    mdatp.set_log_rotation_params(**self.expanded_log_rotate_params)

        def __exit__(self, exc_type, exc_value, exc_tb):
            if self.mdatp_installed and mdatp.is_alive():
                if self.log_level and self.default_log_level != self.log_level:
                    log.info(f'Re-setting log level to default [{self.default_log_level}]')
                    mdatp.set_log_level(self.default_log_level)

                if hasattr(self, 'expanded_log_rotate_params'):
                    log.info(f'Re-setting mdatp log rotate params to [{({key:str(val)+"MB" for key, val in self.default_log_rotate_params.items()})}]')
                    mdatp.set_log_rotation_params(**self.default_log_rotate_params)

    @staticmethod
    def having_log_folder_issue():
        return mdatp._get_health_parameter('healthy') == 'false' and 'log folder permission issues' in mdatp._get_health_parameter('health_issues')

    @staticmethod
    def fix_log_folder_issue():
        log_dir = constants.LOG_DIR[os_info.platform]

        log_dir_per = fs.get_permission(log_dir)
        expected_log_dir_per = 775

        if log_dir_per != expected_log_dir_per:
            fs.set_permission(log_dir, expected_log_dir_per)
            log.info(f'Fixed log folder permission issue. Previous permission {[log_dir_per]} changed to [{expected_log_dir_per}]')

        if os_info.platform == constants.LINUX_PLATFORM:
            log_dir_acl = fs.get_acl(log_dir, 'group', 'mdatp')
            expected_log_dir_acl = 'rwx'
            if log_dir_acl != expected_log_dir_acl:
                fs.set_acl(log_dir, 'group', 'mdatp', expected_log_dir_acl)
                log.info(f'Fixed ACL for log folder. Previous ACL for group [mdatp] {[log_dir_acl]} changed to [{expected_log_dir_acl}]')

    @staticmethod
    def collect_hot_event_sources(timeout_in_sec, get_command=False):
        cmd = f"{MDATP} {mdatp.cli['hot_event_sources']}"
        if get_command:
            return cmd
        return run_with_output(cmd, timeout_in_sec)
