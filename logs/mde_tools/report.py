import datetime
import json
import logging
import platform
from . import constants, SCRIPT_VERSION
from .mdatp import mdatp
from .events import Events
from .machine import os_details, machine
from .utils import parse_connectivity_test, retrieve_event_id_for_connectivity_results,\
        translate_process_counter_to_string, retrieve_event_id_for_processes, confilicting_orgs,\
        collect_conflicting_binaries, command_exists
from lxml import etree
from .os_version import os_version
import sh

xml_functions = dict()
log = logging.getLogger(constants.LOGGER_NAME)
xml_report_root = etree.Element('mdatp')
xml_general = etree.SubElement(xml_report_root, 'general')
xml_device_info = etree.SubElement(xml_report_root, 'device_info')
xml_events = etree.SubElement(xml_report_root, 'events')

class XmlElement:
    def __init__(self, key, value='', attrs={}):
        self.key = key
        self.value = str(value)
        self.attrs = attrs

    def __repr__(self):
        return "<{klass} @{id:x} {attrs}>".format(
            klass=self.__class__.__name__,
            id=id(self) & 0xFFFFFF,
            attrs=" ".join("{}={!r}".format(k, v) for k, v in self.__dict__.items()),
            )

    def create_subelement_at(self, path):
        etree.SubElement(path, self.key, self.attrs).text = self.value

def register_xml_report_func(path=xml_events, required_package=None):
    """Register function that adds XML elements to the report.xml file.
    path: the request path within the XML to append the XML elements to.
    Each function should return a list of new XML elements to append to the requested path.
    """
    def decorator(func):
        def wrapper():
            elements = func()
            # If function didn't return any value
            if not elements:
                log.debug(f'{func.__name__} function not returned any elements')
                return
            # If function returned single XmlElement make it iterable
            if isinstance(elements, XmlElement):
                elements = [elements]
            for element in elements:
                log.debug(f'Adding {element.key} to {path.tag}')
                element.create_subelement_at(path)
        if required_package and command_exists(required_package) == False:
            log.warn(f'Skipping report generator [{func.__name__}] as {required_package} is not installed')
        else:
            xml_functions[func.__name__] = wrapper
        return wrapper
    return decorator

@register_xml_report_func(path=xml_general)
def populate_general_information():
    return [
        XmlElement('script_version', SCRIPT_VERSION),
        XmlElement('script_run_time', datetime.datetime.utcnow().isoformat()),
    ]

@register_xml_report_func(path=xml_device_info)
def populate_device_info():
    if command_exists('mdatp'):
        log.info('MDATP installed')
        health_json = mdatp.health_data(as_json=True)
        health_json = json.loads(health_json) if health_json else dict()

        processes_info = mdatp.check_mdatp_processes_status()
    else:
        health_json = None

    os_dependent_elements = list()
    os_info = os_details()
    if os_info.platform == constants.MACOS_PLATFORM:
        macos_version = f'{os_info.version} ({os_info.build})'
        os_dependent_elements.extend([XmlElement('macos_version', macos_version, {'display_name': 'macOS Version'})])

    if os_info.platform == constants.LINUX_PLATFORM:
        os_dependent_elements.append(XmlElement('linux_distro', os_info.distro, {'display_name': 'Distribution'}))
        if command_exists('auditd'):
            auditd_status = mdatp.auditd_status(full=False)
            os_dependent_elements.append(XmlElement('auditd_status', auditd_status, {'display_name': 'Audit Status'}))
            auditd_status = mdatp.auditd_status(full=True)
            processes_info['mdatp_audisp_plugin'] = auditd_status.count('mdatp_audisp_plugin')
            os_dependent_elements.append(XmlElement('audisp_plugin_status', translate_process_counter_to_string(processes_info['mdatp_audisp_plugin']), {'display_name': 'Audisp plugin Status'}))
            os_dependent_elements.append(XmlElement('conflicting_binaries', collect_conflicting_binaries(mdatp.auditd_loaded_rules()), {'display_name': 'Conflicting Binaries'}))
            mde_netfilter_package = machine.query_installed_package('mde-netfilter')
            mde_netfilter_version = "Not installed" if mde_netfilter_package.version is None else mde_netfilter_package.version
            os_dependent_elements.append(XmlElement('mde_netfilter_version', mde_netfilter_version, {'display_name': 'MDE Net Filter version'}))
        else:
            auditd_status = "Auditd not installed"
            os_dependent_elements.append(XmlElement('auditd_status', auditd_status, {'display_name': 'Audit Status'}))


    mdatp_dependent_elements = list()
    if health_json is None:
        mdatp_dependent_elements.append(XmlElement('MDATP_Status', 'Not Installed', {'display_name': 'MDATP Status'}))
    else:
        mdatp_dependent_elements.append(XmlElement('device_id', health_json.get('edrMachineId', ''), {'display_name': 'Device ID'}))
        mdatp_dependent_elements.append(XmlElement('org_id', health_json.get('orgId', ''), {'display_name': 'Organization ID'}))
        mdatp_dependent_elements.append(XmlElement('sense_version', health_json.get('appVersion', ''), {'display_name': 'Sense Version'}))
        mdatp_dependent_elements.append(XmlElement('sense_config_version', health_json.get('edrConfigurationVersion', ''), {'display_name': 'Sense Configuration Version'}))
        mdatp_dependent_elements.append(XmlElement('av_signature_version', health_json.get('definitionsVersion', ''), {'display_name': 'Defender AV Security Intelligence Version'}))
        mdatp_dependent_elements.append(XmlElement('av_engine_version', health_json.get('engineVersion', ''), {'display_name': 'Defender AV engine Version'}))
        mdatp_dependent_elements.append(XmlElement('release_ring', health_json.get('releaseRing', ''), {'display_name': 'MDE Release Ring Name'}))
        mdatp_dependent_elements.append(XmlElement('real_time_protection_enabled', health_json.get('realTimeProtectionEnabled', {}).get('value', ''), {'display_name': 'AV Real Time Protection Enabled'}))
        mdatp_dependent_elements.append(XmlElement('real_time_protection_available', health_json.get('realTimeProtectionAvailable', ''), {'display_name': 'AV Real Time Protection Available'}))
        mdatp_dependent_elements.append(XmlElement('real_time_protection_subsystem', health_json.get('realTimeProtectionSubsystem', ''), {'display_name': 'AV Real Time Protection Subsystem'}))
        mdatp_dependent_elements.append(XmlElement('passive_mode_enabled', health_json.get('passiveModeEnabled', {}).get('value', ''), {'display_name': 'Passive Mode Enabled'}))
        mdatp_dependent_elements.append(XmlElement('healthy', health_json.get('healthy', ''), {'display_name': 'Healthy'}))
        mdatp_dependent_elements.append(XmlElement('edr_process_status', translate_process_counter_to_string(processes_info['edr']), {'display_name': 'EDR Process Status'}))
        mdatp_dependent_elements.append(XmlElement('av_process_status', translate_process_counter_to_string(processes_info['av']), {'display_name': 'AV Process Status'}))
        mdatp_dependent_elements.append(XmlElement('telemetry_process_status', translate_process_counter_to_string(processes_info['telemetryd_v1'] + processes_info['telemetryd_v2']), {'display_name': 'Telemetry Process Status'}))
        mdatp_dependent_elements.append(XmlElement('conflicting_agents', confilicting_orgs(), {'display_name': 'Conflicting Agents'}))

    # davlevi - Note: We must make sure that every function here *can't* throw, otherwise the report won't include any device information, please wrap with try catch.
    return [
        XmlElement('device_name', platform.node(), {'display_name': 'Device Name'}),
        XmlElement('host_name', machine.get_hostname(), {'display_name': 'Host Name'}),
        XmlElement('os_family', platform.system(), {'display_name': 'OS Family'}),
        XmlElement('os_name', f'{os_info.distro} {os_info.version}', {'display_name': 'OS Name'}),
        XmlElement('os_kernel_version', platform.release(), {'display_name': 'OS Kernel Version'}),
        XmlElement('architecture', platform.machine(), {'display_name': 'OS Architecture'})] + \
        mdatp_dependent_elements + os_dependent_elements

@register_xml_report_func(path=xml_events)
def os_compatibility_event():
    os_info = os_details()
    if os_info.platform == constants.MACOS_PLATFORM:
        mac_version = float('.'.join(os_info.version.split('.')[:2]))
        if mac_version < constants.MINIMUM_MACOS_VERSION:
            return XmlElement('event', attrs={'id': f'{constants.MACOS_PREFIX}{Events.EVINRONMENT_UNSUPPORTED_OS.value}'})
    elif os_info.platform == constants.LINUX_PLATFORM:
        version = os_version.to_version(os_info.version)
        if (
            (os_info.distro == 'Ubuntu' and version < constants.MINIMUM_UBUNTU_VERSION) or
            (os_info.distro.startswith('CentOS') and version < constants.MINIMUM_CENTOS_VERSION) or
            (os_info.distro.startswith('Red Hat') and version < constants.MINIMUM_RHEL_VERSION)
           ):
            return XmlElement('event', attrs={'id': f'{constants.LINUX_PREFIX}{Events.EVINRONMENT_UNSUPPORTED_OS.value}'})
        # Check preview for informational notification
        if (
            (os_info.distro.startswith('CentOS') or os_info.distro.startswith('Red Hat')) and
            (constants.CENTOS_RHEL_PREVIEW_RANGE.min <= version <= constants.CENTOS_RHEL_PREVIEW_RANGE.max)
        ):
            return XmlElement('event', attrs={'id': f'{constants.LINUX_PREFIX}{Events.ENVIRONMENT_PREVIEW_OS.value}'}) 


@register_xml_report_func(path=xml_events, required_package='mdatp')
def connectivity_events():
    # Create a function variable that we can update within the callback
    connectivity_events.connectivity_result = ''
    def print_and_update_result(data):
        # Print data to show progress while the connectivity test is running (remove double \n)
        print(data, end=' ')
        connectivity_events.connectivity_result += data
    try:
        log.info('Executing connectivty test (this may take up to a minute)')
        sh.mdatp("connectivity", "test", _out=print_and_update_result)
    except Exception as e:
        log.error(f"Failed to run connectivity test: {e}")
    if not connectivity_events.connectivity_result:
        log.warn('Connectivity test failed')
        return
    result = parse_connectivity_test(connectivity_events.connectivity_result)
    return [
        XmlElement('event', attrs={'id': retrieve_event_id_for_connectivity_results(result['edr_cnc'], Events.CONNECTIVITY_EDR_CNC_GOOD.value, Events.CONNECTIVITY_EDR_CNC_WARN.value, Events.CONNECTIVITY_EDR_CNC_ERROR.value)}),
        XmlElement('event', attrs={'id': retrieve_event_id_for_connectivity_results(result['edr_cyber'], Events.CONNECTIVITY_EDR_CYBER_GOOD.value, Events.CONNECTIVITY_EDR_CYBER_WARN.value, Events.CONNECTIVITY_EDR_CYBER_ERROR.value)}),
        XmlElement('event', attrs={'id': retrieve_event_id_for_connectivity_results(result['av'], Events.CONNECTIVITY_AV_GOOD.value, Events.CONNECTIVITY_AV_WARN.value, Events.CONNECTIVITY_AV_ERROR.value)})
    ]

@register_xml_report_func(path=xml_events, required_package='mdatp')
def process_running():
    processes_info = mdatp.check_mdatp_processes_status()
    return XmlElement('event', attrs={'id': retrieve_event_id_for_processes(processes_info, Events.PROCESSES_RUNNIN_GOOD.value, Events.PROCESSES_RUNNIN_ERROR.value)})

@register_xml_report_func(path=xml_events, required_package='auditd')
def os_conflicting_binaries():
    os_info = os_details()
    if os_info.platform == constants.LINUX_PLATFORM:
        rules = mdatp.auditd_loaded_rules()
        if rules and len(collect_conflicting_binaries(rules)) > 0:
            return XmlElement('event', attrs={'id': f'{constants.LINUX_PREFIX}{Events.CONFLICTING_BINARIES.value}'})
    return

@register_xml_report_func(path=xml_events)
def client_autentication_status():
    os_info = os_details()
    os_prefix = constants.MACOS_PREFIX

    if os_info.platform == constants.LINUX_PLATFORM:
        os_prefix = constants.LINUX_PREFIX

    identity = mdatp.get_edr_identity()

    is_idenity_exists = identity is not None

    is_registered = False
    if identity:
        try:
            is_registered = identity["registrationComplete"]
        except:
            is_registered = False

    
    if is_idenity_exists:
        if is_registered:
            return XmlElement('event', attrs={'id': f'{os_prefix}{Events.ANTI_SPOOFING_STABLE.value}'})
        else:
            return XmlElement('event', attrs={'id': f'{os_prefix}{Events.ANTI_SPOOFING_UNSTABLE.value}'})
    else:
        return  XmlElement('event', attrs={'id': f'{os_prefix}{Events.ANTI_SPOOFING_READY.value}'})
