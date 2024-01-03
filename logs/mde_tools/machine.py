
from .utils import wait, run_with_output, run, DEBUG_MODE, ONBOARDING_PACKAGE, ONBOARDING_SCRIPTS,COLLECTION_DIR, error
from mde_tools import constants
import logging
import platform
import distro as distro_info
from subprocess import Popen
import os, time, re, tempfile
import sys
import socket
import json

log = logging.getLogger(constants.LOGGER_NAME)

class os_details:

    platform = None
    package_manager = None
    version = None
    distro = None

    def __init__(self):
        self.platform, self.distro, self.package_manager, self.version, self.build = self._identify_platform()
        log.debug(f"platform: [{self.platform}]")
        log.debug(f"distribution: [{self.distro}] version: [{self.version}]")
        log.debug(f"package manager: [{self.package_manager}]")


    def _identify_platform(self):
        if platform.system() == 'Darwin':
            sw_vers = run_with_output("sw_vers")
            version = self._find_regex(sw_vers, r'ProductVersion:\s+(\S+)')
            build = self._find_regex(sw_vers, r'BuildVersion:\s+(\S+)')
            return (constants.MACOS_PLATFORM, "Darwin", "brew", version, build)

        if platform.system() == "Linux":
            package_mapping = {
                "debian": "apt", # ubuntu [deb]
                "fedora": "yum", # rhel, centos, oracle [rpm]
                "sles": "zypper", # sles [rpm]
                "centos": "yum"
            }

            version = distro_info.version(best=True)
            for like, package_manager in package_mapping.items():
                if like in [distro_info.like(), distro_info.id()]:
                    return (constants.LINUX_PLATFORM, distro_info.name(), package_manager, version, "")
            return (constants.LINUX_PLATFORM, distro_info.name(), None, version, "")
        raise NotImplementedError("unknown platform: {}".format(platform.system()))


    def _find_regex(self, text, expression):
        matches = re.findall(expression, text)
        if matches is None or len(matches) == 0:
            return None
        return ''.join(matches[0])

    def is_big_sur_and_up(self) -> bool:
        if self.platform is constants.LINUX_PLATFORM:
            return False
        version_parts = self.version.split(".")
        major_ver = version_parts[0] if len(version_parts)>0 else 0
        return int(major_ver) >= 11

class package:
    name = None
    version = None
    installed = False
    source = None

    def __init__(self, name, version = None, is_installed = False, source = None):
        self.name = name
        self.version = version
        self.installed = is_installed
        self.source = source
    
    def __repr__(self):
        return f'Package name: {self.name}, version: {self.version}, installed? {self.installed}, source: {self.source}'

class machine:
    download_folder = None
    username = None
    hostname = None
    platform = None
    distro = None
    os_version  = None
    package_manager = None
    start_time = time.time()
    temp_folder = None

    @staticmethod
    def get_start_time():
        return machine.start_time
    
    @staticmethod
    def get_platform():
        if machine.platform is None:
            details = os_details()
            machine.platform = details.platform
            machine.package_manager = details.package_manager
            machine.os_version = details.version
            machine.distro = details.distro
        return machine.platform

    @staticmethod
    def is_installed(appname):
        return run_with_output(f"which {appname}") is not None

    @staticmethod
    def create_multiple_process_events(no_of_events):
        for event_number in range(no_of_events):
            run(f"ls ./test_{event_number+1} &> /dev/null", False)
            time.sleep(0.01)
        
    @staticmethod
    def create_multiple_file_events(no_of_events):
        possible_paths = ['/bin/ls', 'usr/bin/ls']
        possible_paths = [path for path in possible_paths if os.path.exists(path)]
        if len(possible_paths) == 0:
            raise Exception("could not find executable binary")
        exec_path = possible_paths[0]
        temp_dir = machine.get_temp_folder()
        
        for event_number in range(no_of_events):
            dest_path = os.path.join(temp_dir, f"test_{event_number+1}.ls")
            run(f"cp {exec_path} {dest_path}", False)
            time.sleep(0.01)

        run(f"rm {temp_dir}/test_*")

    @staticmethod
    def create_multiple_network_events(no_of_events, timeout = 60):
        start_time = time.time()
        # local capping is disabled by configuration, we can use the same port #
        def connect_event():
            try:
                ipv6_ip = '2a02:26f0:12f:2a3::356e 80'
                machine.create_ipv6_conn(ipv6_ip)
                return 1
            except Exception as ex:
                log.warning(f"failed to complete events: {ex}")
                return 0

        connection_events = 0
        while( connection_events < no_of_events and (time.time() - start_time) < timeout ):
            connection_events = connection_events + connect_event()
        elapsed_time = time.time() - start_time
        log.debug(f"{connection_events} network events created [{elapsed_time:.2f}s]")
        return connection_events == no_of_events

    @staticmethod
    def trigger_mac_login_event():
        return run('sudo scutil <<< "notify State:/Users/ConsoleUser"')

    @staticmethod
    def get_sense_guid():
        logs = machine.get_logs_dir()
        for logs_dir in [logs, os.path.join(logs, 'rotated')]:
            sense_guid_line = machine._get_last_line_from_logs(logs_dir, "sense_guid")
            if sense_guid_line is not None:
                return machine._parse_from_json(sense_guid_line, "sense_guid")
        return None

    @staticmethod
    def find_messages_in_log(key):
        messages_array = []
        lines = machine._get_last_line_from_logs(machine.get_logs_dir(), key, get_all_lines=True)
        if lines is None:
            return None
        for line in lines:
            time_since_epoch = machine._parse_time_from_log_message(line)
            if time_since_epoch is None:
                continue
            if time_since_epoch > machine.start_time:
                messages_array.append(line)
        if len(messages_array) > 0:
            return messages_array
        return None

    @staticmethod
    def _parse_time_from_log_message(line):
        time_string_list = re.findall(r'\[.+?\]\[(.+?)\]\[.+?\]', line)
        if time_string_list is None or len(time_string_list) == 0:
            log.info("failed to parse datetime from log mesaage")
            return None
        # Expected format: [2020-04-28 05:14:25.659656 UTC]
        time_obj = time.strptime(time_string_list[0].split('.')[0], "%Y-%m-%d %H:%M:%S")
        # Return time since epoch in UTC
        return time.mktime(time_obj) - time.altzone

    @staticmethod
    def last_log_message_time(key):
        line = machine._get_last_line_from_logs(machine.get_logs_dir(), key)
        if line is None:
            return None
        time_since_epoch = machine._parse_time_from_log_message(line)
        return time_since_epoch

    @staticmethod
    def verify_msg_in_logs(message, ref_time=None, timeout_sec = 5):
        if ref_time is None:
            ref_time = machine.get_start_time()
        
        log.info(f"Looking for [{message}] in logs")
        start_time = time.time()
        
        while time.time() - start_time < timeout_sec:
            last_log_msg_time = machine.last_log_message_time(message)
            
            if last_log_msg_time is None:
                wait(5, "retry: waiting for msg to appear in log")
                continue

            delta = last_log_msg_time - ref_time
            log.debug(f"last message time: {last_log_msg_time}. delta = {delta}")
            
            if delta < 0:
                wait(5, "retry: waiting for updated msg to appear in log")
                continue
            
            return True
        
        return False

    @staticmethod
    def get_hostname():
        if machine.hostname is None:
            platform = machine.get_platform()
            if platform == 'macOS':
                machine.hostname = run_with_output("scutil --get LocalHostName")
            if platform == 'Linux':
                machine.hostname = run_with_output("/bin/hostname")
            log.info(f"Hostname: [{machine.hostname}]")
        return machine.hostname

    @staticmethod
    def get_username():
        if machine.username is None:
            machine.username = str(run_with_output("whoami"))
        return machine.username

    @staticmethod
    def create_executable(filename):
        return run(f"cp /bin/ls {filename}")

    @staticmethod
    def create_ipv6_conn(ipv6_ip):
        return run(f"nc {ipv6_ip}")

    @staticmethod
    def download_file(url, filename=None):
        if filename is None:
            filename = os.path.join(machine.get_download_folder(), url.split('/')[-1])
        command = f"curl -o {filename} {url}"
        if machine.get_platform() == 'macOS':  ## MacOS curl is different as we used in linux so we installed similar version from brew to make parity on our events
            log.info("trying to use newest curl version from brew MacOS")
            curl_version = run_with_output('ls /usr/local/Cellar/curl/')
            log.debug(f"curl_version: {curl_version} type: {type(curl_version)}")
            if curl_version not in ("", None):
                new_curl_path = f"/usr/local/Cellar/curl/{curl_version}/bin/curl"
                command = f"{new_curl_path} -o {filename} {url}"
        log.debug(f"curl command: {command}")
        success = run(command)
        log.info(f"file downloaded: {filename} [{'ok' if success else 'fail'}]")
        return success

    @staticmethod
    def file_exists_in_download_folder(filename):
        full_name = os.path.join(machine.get_download_folder(), filename)
        return os.path.exists(full_name)
    
    @staticmethod
    def run_process(command):
        return run(command)

    @staticmethod
    def get_temp_folder():
        if machine.temp_folder is None:
            machine.temp_folder = tempfile.gettempdir()
        return machine.temp_folder

    @staticmethod
    def set_temp_folder(temp_folder):
        machine.temp_folder = temp_folder
        log.info(f"temp folder set: [{machine.temp_folder}]")
    
    @staticmethod
    def get_collection_folder():
        return os.path.join(machine.get_temp_folder(),COLLECTION_DIR)

    @staticmethod
    def copy_to_collection_folder(filename):
        collection_folder = machine.get_collection_folder()
        log.debug(f"os.path.exists(collection_folder) {os.path.exists(collection_folder)}")
        if not os.path.exists(collection_folder) and not run(f"sudo mkdir {collection_folder}"):
            log.error("cannot create temp directory")
            return False
        log.debug(f"os.path.exists(collection_folder) {collection_folder}, {os.path.exists(collection_folder)} after creation")

        if not run(f"sudo cp '{filename}' '{collection_folder}'"):
            log.error(f"cannot copy {filename} to collection folder")
            return False
        
        return True

    @staticmethod
    def copy_dir_to_collection_folder(folder_path, target_name):
        collection_folder = machine.get_collection_folder()
        if not os.path.exists(collection_folder) and not run(f"sudo mkdir {collection_folder}"):
            log.error("cannot create temp directory")
            return False

        if not run(f"sudo cp -r '{folder_path}' '{collection_folder}/{target_name}'"):
            log.error(f"cannot copy {folder_path} to collection folder")
            return False
        
        return True

    @staticmethod
    def move_file_to_target_folder(file_path, target_folder):
        if not run(f"sudo mv '{file_path}' '{target_folder}'"):
            log.error(f"cannot move {file_path} to {target_folder}")
            return False
        return True
        
    
    @staticmethod
    def get_download_folder():
        if machine.download_folder is None:
            platform = machine.get_platform()
            if  platform == 'macOS':
                machine.download_folder = os.path.join("/","Users",machine.get_username(),"Downloads")
            elif platform == 'Linux':
                machine.download_folder = run_with_output("xdg-user-dir DOWNLOAD")
            log.debug(f"Download folder: [{machine.download_folder}]")
        return machine.download_folder

    @staticmethod
    def change_permissions(filename):
        return run(f"sudo chmod 666 {filename}")

    @staticmethod
    def get_logs_dir():
        platform = machine.get_platform()
        if platform == 'macOS':
            return '/Library/Logs/Microsoft/mdatp'
        if platform == 'Linux':
            return '/var/log/microsoft/mdatp'
        raise Exception("unknown platform")
        
    @staticmethod
    def get_process_ids(proc_names, excluded_processes=[]):
        pids = set()
        for proc_name in proc_names:
            command = f"ps aux | grep {proc_name} | grep -v grep"
            for excluded_proc in excluded_processes:
                command = command + f" | grep -v {excluded_proc}"
            result = os.popen(command).read()
            if result is None:
                continue
            lines = result.strip().split('\n')
            for line in lines:
                parts = line.split()
                if len(parts)>1:
                    pids.add(parts[1])
        return list(pids)

    @staticmethod
    def _check_duplicates_process(output):
        pids = []
        new_output = []
        for process in output:
            pid = process.split()[1]
            if pid in pids:
                continue
            pids.append(pid)
            new_output.append(process)
        return new_output


    @staticmethod
    def get_process_info(process_names):
        output = []
        for proc_name in process_names:
            process_data = os.popen(f"ps aux | grep {proc_name} | grep -v grep").read().strip().split("\n")
            if process_data != None or process_data != '':
                [output.append(process) for process in process_data if process not in output and process != None and process != '']
        new_output = machine._check_duplicates_process(output)
        return "\n".join(new_output)


    @staticmethod
    def unzip_package(package_name,timeout = 30):
        end_time = time.time() + timeout
        if not machine.get_package_filename(package_name):
            log.debug(f"package was not found in download folder [{package_name}]")
            return None
        download_folder = machine.get_download_folder()
        unzip_output = run_with_output(f'unzip -o "{os.path.join(download_folder, package_name)}" -d {download_folder}', verbose=True)
        while time.time() < end_time:
            if unzip_output is not None:
                break
            wait(2, "wait for the unzip to finish")
        script_name = re.findall("inflating: (.+?)(?:\n|$)", unzip_output)[0].strip()
        log.debug(f"script name: {script_name}")
        return script_name

    @staticmethod
    def get_package_filename(package_filename, timeout=15):
        start_time = machine.get_start_time()
        end_time = time.time() + timeout
        while time.time() < end_time:
            for filename in os.listdir(machine.get_download_folder()):
                if ".crdownload" in filename:
                    continue
                # take the package that was created after the test had started
                file_create_time = os.path.getmtime(os.path.join(machine.get_download_folder(), filename))
                if package_filename in filename and file_create_time > start_time:
                    return filename
            wait(1, "wait for package to download")
        return None
    
    @staticmethod
    def clean_downloads_folder():
        run(f"rm -rf {os.path.join(machine.get_download_folder(), '*DefenderATP*')}")
    
    @staticmethod
    def package_downloaded(package_filename, timeout = 120):
        return machine.get_package_filename(package_filename,timeout) is not None

    @staticmethod
    def delete_package_files(zip_package,script_name):
        run(f"rm -rf {os.path.join(machine.get_download_folder(), zip_package)}")
        run(f"rm -rf {os.path.join(machine.get_download_folder(), script_name)}")

    @staticmethod
    def delete_diy_files():
        run("rm -rf ~/Downloads/*DIY*")
        run("rm -rf ~/Downloads/__MACOSX")

    @staticmethod
    def _get_onboarding_script():
        download_folder = machine.get_download_folder()
        files = os.listdir(download_folder)
        onboarding_script = None
        for script in ONBOARDING_SCRIPTS:
            if script in files:
                onboarding_script = script
        return onboarding_script

    @staticmethod
    def _get_last_line_from_logs(logs_dir, expression, get_all_lines=False): 
        temp_filename = os.path.join(machine.get_temp_folder(), "config_temp")
        # read all enterprise logs into a single file
        run(f"sudo cat {logs_dir}/microsoft_defender_enterprise* > {temp_filename}", False)
        # read lines from combined log
        output = run_with_output(f"cat {temp_filename}", verbose=False)
        if output is None:
            return None
        lines = output.split('\n')
        lines = [line for line in lines if expression in line]
        # delete temp file
        run(f"rm -rf {temp_filename}", False)

        if len(lines) == 0:
            return None
        if get_all_lines:
            return lines
        return lines[-1]

    @staticmethod
    def get_crash_dump_dir():
        platform = machine.get_platform()
        if platform == 'macOS':
            return '/Library/logs/DiagnosticReports'
        if platform == 'Linux':
            return '/var/crash'
        raise Exception("unknown platform")
    
    @staticmethod
    def _parse_from_json(line, key):
        matches = re.findall(f'\"{key}\":\"(.+?)\"', line)
        if matches is None or len(matches) == 0:
            return None
        return matches[0]

    @staticmethod
    def query_installed_package(package_name):
        command = None
        curr_distro_likes = distro_info.like().split(' ')
        curr_distro_likes.append(distro_info.id())
        if [like for like in curr_distro_likes if like == "debian"]:
            command = f"dpkg-query -W -f=\'\\{{\"Name\":\"${{binary:Package}}\", \"Version\": \"${{Version}}\", \"Status\": \"${{db:Status-Status}}\", \"Source\": \"${{Source}}\"}}\' {package_name}"
        elif [like for like in curr_distro_likes if like in ["sles", "centos", "fedora", "rhel"]]:
            command = f"rpm -qa --qf \'\\{{ \"Name\":\"%{{NAME}}\", \"Version\": \"%{{VERSION}}-%{{RELEASE}}\", \"Status\": \"installed\", \"Source\": \"%{{SOURCEPACKAGE}}\"\\}}\' {package_name}"
        else:
            log.info(f'Could not fetch package details for package {package_name}')
            return package(package_name)

        result = run_with_output(cmd=command, verbose=False)
        try:
            res_dict = json.loads(result)
            is_installed = True if res_dict["Status"] == "installed" else False
            return package(name = res_dict['Name'], version = res_dict["Version"], is_installed = is_installed, source = res_dict['Source'])
        except:
            return package(package_name)
