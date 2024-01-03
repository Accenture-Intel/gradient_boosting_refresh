import os
import sys
from mde_tools.os_version import os_version
from types import SimpleNamespace

# determine if application is a script file or compiled ELF
IS_COMPILED_AS_BINARY = getattr(sys, 'frozen', False)
SUPPORT_TOOL_ROOT_DIRECTORY = os.path.join(os.path.dirname(sys.executable)) if IS_COMPILED_AS_BINARY else os.path.join(os.path.dirname(os.path.realpath(__file__)))
XSLT_FILENAME = 'report.xslt'
XML_FILENAME = 'events.xml'
XSLT_PERF_EPS_REPORT_PATH = os.path.join(SUPPORT_TOOL_ROOT_DIRECTORY, 'perf_eps_top_event_report.xslt')
XSLT_REPORT_PATH = os.path.join(SUPPORT_TOOL_ROOT_DIRECTORY, XSLT_FILENAME)
XML_EVENTS_PATH = os.path.join(SUPPORT_TOOL_ROOT_DIRECTORY, XML_FILENAME)
LOGGER_NAME = 'support_tool'
MINIMUM_MACOS_VERSION = os_version("10.14")
MINIMUM_UBUNTU_VERSION = os_version("16.04")
MINIMUM_CENTOS_VERSION = os_version("6.7")
MINIMUM_RHEL_VERSION = os_version("6.7")
CENTOS_RHEL_PREVIEW_RANGE = SimpleNamespace(min=os_version("6.7"), max=os_version("6.10"))
MACOS_PREFIX = 2
LINUX_PREFIX = 3
LINUX_PLATFORM = 'Linux'
MACOS_PLATFORM = 'macOS'
DLP_DIAGNOSTIC_FILE_PATH = '/Library/Application\ Support/Microsoft/DLP/com.microsoft.dlp.daemon.app/Contents/Resources/Tools/dlp_diagnostic.py'
EXTENDED_ATTR_FILE_PATH = '/Library/Application\ Support/Microsoft/DLP/com.Microsoft.dlp.daemon.app/Contents/Resources/Tools/DisplayExtendedAttributes.py'
NETEXT_CONFIG_FILE_PATH = '/Applications/Microsoft\ Defender.app/Contents/Resources/Tools/netext_config'
WDAV_STATE = {LINUX_PLATFORM: '/var/opt/microsoft/mdatp/wdavstate', MACOS_PLATFORM:'/Library/Application Support/Microsoft/Defender/wdavstate'}
MDATP_MANAGED = {LINUX_PLATFORM:'/etc/opt/microsoft/mdatp/managed/mdatp_managed.json', MACOS_PLATFORM:'/Library/Managed Preferences/com.microsoft.wdav.plist'}
WDAV_CFG = {LINUX_PLATFORM: '/etc/opt/microsoft/mdatp/wdavcfg', MACOS_PLATFORM: '/Library/Application Support/Microsoft/Defender/wdavcfg'}
LOG_DIR = {LINUX_PLATFORM: '/var/log/microsoft/mdatp', MACOS_PLATFORM : '/Library/Logs/Microsoft/mdatp'}
MERGED_CONFIG = {LINUX_PLATFORM: '/var/log/microsoft/mdatp/microsoft_defender_core.log', MACOS_PLATFORM: '/Library/Logs/Microsoft/mdatp/microsoft_defender_core.log'}
MERGED_CONFIG_ROTATED_DIR = {LINUX_PLATFORM : '/var/log/microsoft/mdatp/rotated', MACOS_PLATFORM: '/Library/Logs/Microsoft/mdatp/rotated'}
ENGINEDB_DIR = {LINUX_PLATFORM : '/var/opt/microsoft/mdatp/enginedb', MACOS_PLATFORM : '/Library/Application Support/Microsoft/Defender/enginedb'}
CRASH_REPORTS = {LINUX_PLATFORM : '/var/opt/microsoft/mdatp/crash', MACOS_PLATFORM : '/Library/Logs/DiagnosticReports'}
EXLUSION_RULES="/etc/audit/rules.d/exclude.rules"
RATE_LIMIT_RULES="/etc/audit/rules.d/mdatp.rate_limit.rules"
SKIP_FAULTY_RULES="/etc/audit/rules.d/1_mdatp.skip_faulty_rule.rules"
MDC_CONFIG="/var/lib/waagent/Microsoft.Azure.AzureDefenderForServers.MDE.Linux-*"#<version>"
EBPF_SYSCALLS = "/sys/kernel/debug/tracing/events/syscalls"
EBPF_RAW_SYSCALLS = "/sys/kernel/debug/tracing/events/raw_syscalls"
MDATP_SERVICE_PATH_DEB = "/lib/systemd/system/mdatp.service"
MDATP_SERVICE_PATH_RPM = "/usr/lib/systemd/system/mdatp.service"