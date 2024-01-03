from mde_tools import constants
import io, logging
import json, os, subprocess
import re
from os import path
from .machine import os_details, machine
from .mdatp import mdatp
from pathlib import Path

os_info = os_details()
log = logging.getLogger(constants.LOGGER_NAME)

def find_files(filepath, filename):
    all_files = []
    for file in os.listdir(filepath):
        if file.startswith(filename):
            all_files.append(file)
    return all_files

def get_mde_health():
    health_data = mdatp.health_data(as_json=True)
    if not health_data:
        log.warn("Failed to collect MDE health")
        return None, "health.txt"
    return health_data, "health.txt"

def _get_config(fp):
    filepath = fp
    filename = os.path.basename(fp)
    try:
        if os.path.exists(filepath):
            f = Path(filepath).read_text()
            return f, filepath
        else:
            return None, filepath
    except ValueError:
        log.error(f"Could not load {filename} configuration file")
        return None, filepath

def _get_managed_config_macOS(filepath):
    try:
        tmpfile = '/tmp/mdatp_managed_config_macOS_tmp.json'
        f = None
        if os.path.exists(filepath):
            #in macOS, managed configurations are in plist format. convert plist into json
            subprocess.run(["plutil", "-convert", "json", filepath, "-o", tmpfile, "-r"])
            if os.path.exists(tmpfile):
                f = Path(tmpfile).read_text()
                os.remove(tmpfile)
                return f, filepath
            else:
                log.error("Could not create json file from managed plist file")
                return None, filepath
        else:
            log.error("mdatp managed configurations file doesn't exist on your system")
            return None, filepath
    except ValueError:
        log.error("Could not load managed configuration file")
        return None, filepath

def _find_merged_features(filepath):
    result = None
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as fp:
                # search latest merged config values
                for l_no, line in sorted(enumerate(fp), reverse=True):
                    if 'Features merged with capabilities:' in line:
                        result =  re.sub(".*Features merged with capabilities: ",'', line)
                        break
                return result, filepath
        else:
            return None, filepath
    except ValueError:
            log.error('Could not load mdatp_merged configuration file')
            return None, filepath

def get_wdavcfg_config():
    return _get_config(constants.WDAV_CFG[os_info.platform])

def get_wdavstate_config():
    return _get_config(constants.WDAV_STATE[os_info.platform])

def get_managed_config():
    if machine.get_platform() == constants.MACOS_PLATFORM:
        return _get_managed_config_macOS(constants.MDATP_MANAGED[os_info.platform])
    else:
        return _get_config(constants.MDATP_MANAGED[os_info.platform])

def get_merged_config():
    result = None
    result_fp = None
    merged_config_path = constants.MERGED_CONFIG[os_info.platform]
    merged_config_rotated_dir = constants.MERGED_CONFIG_ROTATED_DIR[os_info.platform]

    result, result_fp = _find_merged_features(merged_config_path)
    if result:
        return result, result_fp
    else:
        all_files = find_files(merged_config_rotated_dir, 'microsoft_defender_core.log')
        #checking in rotated logs
        for filepath in all_files:
            result, result_fp = _find_merged_features(merged_config_rotated_dir + '/' + filepath)
            if result:
                return result, result_fp
    if result is None:
        e = "Merged config not found. Maybe try restarting your mdatp"
        log.error(e)
        return None, result_fp

def write_to_outputStream(writer_fn, description, title):
    result_dict = {}
    result_dict['description'] = description
    result_dict['title'] = title
    result, result_fp = writer_fn()
    if result:
        result_dict['value'] = json.loads(result)
    else:
        result_dict['fileerror'] = f"Could not load {title.lower()} file. Maybe try restarting mdatp."
    result_dict['filepath'] = result_fp
    return result_dict
        
def get_mdatp_config_allchannel():
    outputStream = []
    outputStream.append(write_to_outputStream(writer_fn = get_mde_health, description = "Health output when running 'mdatp health' command", title = "MDE HEALTH"))
    outputStream.append(write_to_outputStream(writer_fn = get_merged_config, description = "Effective value of the mdatp product configurations. Used by the daemon", title = "MERGED CONFIGURATIONS"))
    outputStream.append(write_to_outputStream(writer_fn = get_managed_config, description = "Preferences coming from Enterprise", title = "MANAGED CONFIGURATIONS"))
    outputStream.append(write_to_outputStream(writer_fn = get_wdavcfg_config, description = "Preferences coming from Local User", title = "WDAVCFG CONFIGURATIONS"))
    outputStream.append(write_to_outputStream(writer_fn = get_wdavstate_config, description = "Preferences coming from Product State", title = "WDAVSTATE CONFIGURATIONS"))
    return outputStream