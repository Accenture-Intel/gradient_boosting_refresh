#!/usr/bin/python3
import argparse
import datetime
import os
import sys
import shutil
import typing
import zipfile
import tempfile
import stat
import datetime
from .report import xml_report_root, xml_functions
from .diagnostic import diagnostic_functions, SystemMonitor
from .connectivity_test import perform_test
from .machine import os_details, machine
from .exclude import exclude
from .rate_limiter import rate_limiter
from .skip_faulty_rules import skip_faulty_rules
from .pii_disclaimer import present_disclaimer
from . import perf
from . import constants, logger
from .mdatp import mdatp
from .perf_trace import perf_trace
from .utils import command_exists
from .spike import observe_cpu_mem_spikes
# Add module directory to import paths array
from lxml import etree
from enum import Enum

from . import filesystem as fs
from .mdatp import mdatp
from . import SCRIPT_VERSION
from .utils import run, run_with_output

class PrintHelp(Enum):
    NONE = 0
    MAIN = 1
    CONNECTIVITYTEST = 2

global log
log = logger.set_logger(tempfile.mkstemp(prefix=f'mde_tool_log_{datetime.datetime.utcnow().strftime("%Y_%m_%d_%H_%M_%S")}', suffix='.log')[1], constants.LOGGER_NAME)

def export_report_folder(files_to_copy: typing.Dict[str, typing.Union[str, typing.List[str]]], output_path: str):
    print(files_to_copy)
    # Create report folder
    os.makedirs(output_path, exist_ok=True, mode=stat.S_IRUSR)
    for path_in_dir, file_to_copy in files_to_copy.items():
        dst_in_folder_path = os.path.join(output_path, path_in_dir)
        # Create necessary dirs if not exists
        os.makedirs(dst_in_folder_path, exist_ok=True)
        if isinstance(file_to_copy, list):
            for f in file_to_copy:
                shutil.copy2(f, dst_in_folder_path)
        else:
            shutil.copy2(file_to_copy, dst_in_folder_path)

    # Export log
    shutil.copyfile(log.handlers[0].baseFilename, os.path.join(output_path, 'log.txt'))

    if not constants.IS_COMPILED_AS_BINARY:
        # Export XML
        etree.ElementTree(xml_report_root).write(os.path.join(output_path, 'mde.xml'), pretty_print=True)

        # Add events.xml file to directory
        shutil.copyfile(constants.XML_EVENTS_PATH, os.path.join(output_path, constants.XML_FILENAME))

        # Export HTML
        xslt = etree.parse(constants.XSLT_REPORT_PATH)
        with open(os.path.join(output_path, 'report.html'), 'wb') as writer:
            writer.write(etree.tostring(etree.XSLT(xslt)(xml_report_root), pretty_print=True))

    log.info(f'Folder created at: {output_path}')

def export_report_archive(files_and_data_to_copy: typing.Dict[str, typing.Union[str, typing.List[str]]], output_path: str):
    print(files_and_data_to_copy)
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_writer:
        for path_in_zip, file_to_copy in files_and_data_to_copy.items():
            if isinstance(file_to_copy, list):
                for f in file_to_copy:
                    zip_writer.write(f, arcname=os.path.join(path_in_zip, os.path.basename(f)))
            else:
                # Save the file as the given name (key of the dictionary) or if only directory exists save it as the original filename
                zip_writer.write(file_to_copy, arcname=path_in_zip if os.path.basename(path_in_zip) else os.path.join(os.path.dirname(path_in_zip), os.path.basename(file_to_copy)))

        # Export log
        zip_writer.write(log.handlers[0].baseFilename, arcname='log.txt')
        # Export XML
        zip_writer.writestr('mde.xml', etree.tostring(xml_report_root, pretty_print=True))

        # Currently parsing XSLT crashing in our static binary
        if not constants.IS_COMPILED_AS_BINARY:
            # Add events.xml file to zip
            zip_writer.write(constants.XML_EVENTS_PATH, arcname=constants.XML_FILENAME)

            # Export HTML
            xslt = etree.parse(constants.XSLT_REPORT_PATH)
            zip_writer.writestr('report.html', etree.tostring(etree.XSLT(xslt)(xml_report_root), pretty_print=True))
    os.chmod(output_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    log.info(f'Archive created at: {output_path}')

def collect_diagnostic(args):
    log.info('[MDE Diagnostic]')
    files_dict = {}
    for func_name, func in diagnostic_functions.items():
        try:
            log.info(f'  Collecting {func_name}')
            func_result = func(args)
            # Update files_dict only if function returned a non-empty valid dict
            if isinstance(func_result, dict) and func_result:
                log.info(f'  Adding {", ".join(func_result.keys())} to report directory')
                files_dict.update(func_result)
        except Exception as e:
            log.error(f"  Diagnostics collection encountered an issue at function {func_name} - {str(e)}")
    return files_dict

def generate_report_xml():
    log.info('[Report Generator]')
    for func_name, func in xml_functions.items():
        try:
            log.debug(f'  Generating {func_name}')
            func()
        except Exception as e:
            log.error(f"  Report generator encountered an issue at function {func_name} - {str(e)}")

def log_tool_info():
    log.info(f'XMDEClientAnalyzer Version: {SCRIPT_VERSION}')

def period(duration):
    if duration.lower().endswith('d'):
        return datetime.timedelta(days=int(duration[:-1]))
    elif duration.lower().endswith('h'):
        return datetime.timedelta(hours=int(duration[:-1]))
    elif duration.lower().endswith('m'):
        return datetime.timedelta(minutes=int(duration[:-1]))

    raise argparse.ArgumentTypeError('Wrong time duration. Allowed xd(for days), xh(for hours), xm(for minutes)')

def get_parser():
    parser = argparse.ArgumentParser(description='MDE Diagnostics Tool')
    parser.add_argument('--output', '-o',
                        type=str,
                        default=os.path.join(tempfile.gettempdir(), f'{datetime.datetime.now().strftime("%d_%m_%Y_%H_%M_%S")}_output'),
                        help='Output path to export report')

    parser.add_argument('--no-zip', '-nz',
                        action='store_true',
                        help='If set a directory will be created instead of an archive file')

    parser.add_argument('--force', '-f',
                        action='store_true',
                        help='Will overwrite if output directory exists')

    parser.add_argument('--diagnostic', '-d',
                        action='store_true',
                        help='Collect extensive machine diagnostic information')

    parser.add_argument('--bypass-disclaimer',
                        action='store_true',
                        help='Do not display disclaimer banner')

    parser.add_argument('--mdatp-log',
                        choices={'error', 'warning', 'info', 'debug', 'verbose', 'trace'},
                        help='Set MDATP log level')

    parser.add_argument('--max-log-size',
                        type=int,
                        help='Maximum log file size in MB before rotating(Will restart mdatp)')

    parser.set_defaults(dlpdiagnostic=False)
    parser.set_defaults(performance=False)
    parser.set_defaults(exclude=False)
    parser.set_defaults(trace=False)
    parser.set_defaults(ratelimit=False)
    parser.set_defaults(skipfaultyrules=False)
    parser.set_defaults(connectivitytest=False)
    parser.set_defaults(observespikes=False)
    subparsers = parser.add_subparsers()

    diag_subparser = subparsers.add_parser("dlpdiagnostic", help='Collect dlp diagnostic information')
    diag_subparser.add_argument(dest='target_file', help='target file to examine')

    perf_subparser = subparsers.add_parser("performance", help='Collect extensive machine performance tracing for analysis of a performance scenario that can be reproduced on demand')
    perf_subparser.add_argument('--frequency', type=int, default=1000, help="profile at this frequency")
    perf_subparser.add_argument('--length', type=int, default=10, help="length of time to collect (in seconds)")

    exclude_subparser = subparsers.add_parser("exclude", help="Exclude specific process(es) from audit-d monitoring.")
    exclude_subparser.add_argument("-a", "--arch", help="cpu architecture, used in arch specific syscalls. available: 32, 64. default: 64", type=str, metavar='<32/64>')
    exclude_subparser.add_argument("-e", "--exe", help="exclude by executable name, i.e: bash", action='append', metavar='<executable>')
    exclude_subparser.add_argument("-p", "--pid", help="exclude by process id, i.e: 911", type=int, action='append', metavar='<process id>')
    exclude_subparser.add_argument("-d", "--dir", help="exclude by target path, i.e: /var/foo/bar", action='append', metavar='<directory>')
    exclude_subparser.add_argument("-x", "--exe_dir", help="exclude by executable path and target path, i.e: /bin/bash /var/foo/bar", action='append', nargs=2, metavar=('<executable>','<directory>'))
    exclude_subparser.add_argument("-q", "--queue", help="set dispatcher q_depth size", type=int, metavar='<q_size>')
    exclude_subparser.add_argument("-r", "--remove", help="remove exclusion file", action='store_true')
    exclude_subparser.add_argument("-s", "--stat", help="get statistics about common executables", action='store_true')
    exclude_subparser.add_argument("-l", "--list", help="list auditd rules", action='store_true')
    exclude_subparser.add_argument("-o", "--override", help="Override the existing auditd exclusion rules file for mdatp", action='store_true')
    exclude_subparser.add_argument("-c", "--syscall", help="exclude all process of the given syscall", action='append', metavar='<syscall number>')

    rate_limit_subparser = subparsers.add_parser("ratelimit", help="Set the rate limit for auditd events. Rate limit will update the limits for auditd events for all the applications using auditd, which could impact applications other than MDE.")
    rate_limit_subparser.add_argument("-e", "--enable", help="enable/disable the rate limit with default values", type=str, metavar='<true/false>')
    rate_limit_subparser.add_argument("-r", "--rate", help=argparse.SUPPRESS, type=int, metavar='<rate limit>')
    
    skip_faulty_rules_subparser = subparsers.add_parser("skipfaultyrules", help="Continue loading rules in spite of an error. This summarizes the results of loading the rules. The exit code will not be success if any rule fails to load.")
    skip_faulty_rules_subparser.add_argument("-e", "--enable",
                                             help="enable/disable loading of rules in spite of an error.",
                                             default='true',
                                             choices={'true', 'false'})
    
    tracing_subparser = subparsers.add_parser('trace',help='Use OS tracing facilities to record Defender performance traces.', epilog='On Linux, lttng needs to be installed')
    tracing_subparser.add_argument('--length', default=500, help='Length of time to record the trace (in seconds).', type=int)
    tracing_subparser.add_argument('--mask', default=18446744073709551615, help='Mask to select with event to trace. Defaults to all')

    spikes_subparser = subparsers.add_parser("observespikes", help='Collect the process logs in case of spike or mdatp crash')
    spikes_subparser.add_argument('--upload', action='store_true', help='Upload to azure storage account')
    spikes_subparser.add_argument('--account-name', help='Azure storage account name')
    spikes_subparser.add_argument('--account-key', help='Azure storage account key')
    spikes_subparser.add_argument('--container-name', help='Azure storage container name')
    spikes_subparser.add_argument('--duration', type=period, help='Monitor for duration(ex: 1d, 6h, 2m')
    spikes_subparser.add_argument('--sampling-rate', type=int, default=5, help='Monitoring frequncy rate in seconds')
    spikes_subparser.add_argument('--mem', type=int, default=250000, help='Memory threshold in KB')
    spikes_subparser.add_argument('--cpu', type=int, default=50, help='CPU threshold in percentage')

    connectivitytest_subparser = subparsers.add_parser("connectivitytest", help="Perform connectivity test for MDE")
    connectivitytest_subparser.add_argument("-o", '--onboarding-script', type=str, help="Path to onboarding script")
    connectivitytest_subparser.add_argument("-g", '--geo', type=str, help="Geo string to test <US|UK|EU|AU>")

    perf_subparser.set_defaults(performance=True)
    exclude_subparser.set_defaults(exclude=True)
    rate_limit_subparser.set_defaults(ratelimit=True)
    diag_subparser.set_defaults(dlpdiagnostic=True)
    tracing_subparser.set_defaults(trace=True)
    skip_faulty_rules_subparser.set_defaults(skipfaultyrules=True)
    spikes_subparser.set_defaults(observespikes=True)
    connectivitytest_subparser.set_defaults(connectivitytest=True)

    return { 'parser': parser, 'connectivitytest_subparser': connectivitytest_subparser }

def mandatory_args(args):
    if not (args.diagnostic or args.performance or args.exclude or args.trace or args.ratelimit or args.skipfaultyrules or args.connectivitytest or args.observespikes):
        return PrintHelp.MAIN
    if args.connectivitytest and not (args.geo or args.onboarding_script):
        return PrintHelp.CONNECTIVITYTEST
    PrintHelp.NONE

#exclude should not run with perf or diagnostics
def mutually_excluded(args):
    return not (args.exclude and (args.performance or args.diagnostic))

#rate limit should not run with perf or diagnostics
def mutually_rate_limit(args):
    return not (args.ratelimit and (args.performance or args.diagnostic))

#skip faulty rules should not run with perf or diagnostics
def mutually_skip_faulty_rules(args):
    return not (args.skipfaultyrules and (args.performance or args.diagnostic))

def main():
    log_tool_info()

    parsers = get_parser()
    parser = parsers['parser']
    args = parser.parse_args()

    help = mandatory_args(args)
    if help == PrintHelp.MAIN:
        parser.print_help()
        parser.exit()
    elif help == PrintHelp.CONNECTIVITYTEST:
        parsers['connectivitytest_subparser'].print_help()
        parser.exit()

    if not mutually_excluded(args):
        parser.error('Performance/Diagnostics and Exclude should be used individually')

    if not mutually_rate_limit(args):
        parser.error('Performance/Diagnostics and Rate limit should be used individually')

    if not mutually_skip_faulty_rules(args):
        parser.error('Performance/Diagnostics and Skip Faulty Rules should be used individually')

    output_path = args.output if args.no_zip else args.output + '.zip'
    if args.trace:
        if os_details().platform == constants.LINUX_PLATFORM:
            log.info("Linux performance tracing is not supported.")
            sys.exit(0)
        trace_path = perf_trace(args)
        if args.no_zip:
            export_report_folder(trace_path, output_path)
        else:
            export_report_archive(trace_path, output_path)
        return

    if args.connectivitytest:
        perform_test(args.geo, args.onboarding_script)
        sys.exit(0)

    # Verify privileges:
    if os.geteuid() != 0 and not args.trace:
        parser.error('Please run this tool using `sudo`')

    if args.exclude:
        if os_details().platform != constants.LINUX_PLATFORM:
            parser.error('Exclude is currently supported only on Linux')
    
    if args.ratelimit:
        if os_details().platform != constants.LINUX_PLATFORM:
            parser.error('Rate limit is currently supported only on Linux')

    if args.skipfaultyrules:
        if os_details().platform != constants.LINUX_PLATFORM:
            parser.error('Skipping faulty rules is currently supported only on Linux')

    if command_exists('mdatp') and mdatp.having_log_folder_issue():
        mdatp.fix_log_folder_issue()

    if args.observespikes:
        if args.upload and args.account_key is None and args.account_name is None and args.container_name is None:
            parser.error("Required --account-name, --account-key, --container-name with --upload")

        if os_details().platform != constants.LINUX_PLATFORM:
            parser.error('Observing memory or cpu spikes is currently supported only on Linux')
        try:
            observe_cpu_mem_spikes(args)
        except Exception as e:
            log.error(f"Exception while observing cpu or memory spikes {e}")
        return

    with mdatp.LogManager(args.mdatp_log, args.max_log_size), SystemMonitor() as system_monitor:
        if not args.bypass_disclaimer:
            if not present_disclaimer():
                return

        system_monitor.info()
        files_dict = dict()
        if args.diagnostic or args.performance:
            if os.path.exists(output_path) and not args.force:
                parser.error('Chosen path already exists, please select non-existing path to export')

            files_dict = collect_diagnostic(args)
            if args.performance:
                #TODO: add it to checked prerequisites?
                if os_details().platform == constants.LINUX_PLATFORM:
                    if not command_exists('perf'):
                        parser.error('perf is not installed')

                    files_dict["perf_benchmark.tar.gz"] = perf.capture_on_linux(secs=args.length,
                                                                            frequency=args.frequency)
                else:
                    files_dict["perf_benchmark.tar.gz"] = perf.capture_on_macos(secs=args.length,
                                                                            frequency=args.frequency)

            files_dict.update(system_monitor.stop())
            # Generate Report XML
            generate_report_xml()

            # Export report
            if args.no_zip:
                export_report_folder(files_dict, output_path)
            else:
                export_report_archive(files_dict, output_path)
        elif args.ratelimit:
            rate_limiter(args)
        elif args.skipfaultyrules:
            skip_faulty_rules(args)
        else:
            exclude(args)
