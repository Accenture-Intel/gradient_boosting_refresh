from .machine import os_details
from . import constants
from .utils import run, run_with_output

import logging
import os
import sys
import pathlib
import shutil
import subprocess
import tempfile

log = logging.getLogger(constants.LOGGER_NAME)

def check_prerequisite():
    log.info('Checking prerequisites...')
    platform = os_details().platform

    # TODO: Add Linux support
    if os_details().platform == constants.LINUX_PLATFORM:
        log.info('Linux is not supported.')
        return

    elif platform == constants.MACOS_PLATFORM:
        log.info('Checking for dynamic tracing profile....')
        try:
            output = subprocess.check_output('profiles list'.split(), encoding='UTF-8')
            if '5A1D74B2-DF88-5304-930A-D34383D28D20' not in output:
                log.error('Dynamic tracing profile not installed. Please approve the profile\'s installation in order to be able to enable tracing.')
                path = "./xcamp-manifest-enable-dynamic-signposts.mobileconfig"
                if not constants.IS_COMPILED_AS_BINARY:
                    path = os.path.join(os.path.dirname(__file__), "macOS_tracing/xcamp-manifest-enable-dynamic-signposts.mobileconfig")
                subprocess.check_call(f'open {path}'.split())
                sys.exit(-1)

        except subprocess.CalledProcessError as e:
            log.error('Failed to get list of profiles')
            sys.exit(-1)
    else:
        log.error('Unsupported platform')
        return

def turn_on_tracing(args):
    mask = args.mask

    if os_details().platform == constants.MACOS_PLATFORM:
        run('notifyutil -s com.microsoft.wdav.eventprocess.level 12')
        run('notifyutil -p com.microsoft.wdav.eventprocess.level')
        run('notifyutil -s com.microsoft.wdav.eventprocess.keywords ' + str(mask))
        run('notifyutil -p com.microsoft.wdav.eventprocess.keywords')
        run('notifyutil -s com.microsoft.wdav.eventprocess.mpengine.level 1')
        run('notifyutil -p com.microsoft.wdav.eventprocess.mpengine.level')

def turn_off_tracing():

    if os_details().platform == constants.MACOS_PLATFORM:
        run('notifyutil -s com.microsoft.wdav.eventprocess.level 1')
        run('notifyutil -p com.microsoft.wdav.eventprocess.level')
        run('notifyutil -s com.microsoft.wdav.eventprocess.keywords 0')
        run('notifyutil -p com.microsoft.wdav.eventprocess.keywords')
        run('notifyutil -s com.microsoft.wdav.eventprocess.mpengine.level 0')
        run('notifyutil -p com.microsoft.wdav.eventprocess.mpengine.level')

def run_tracing_mac(args):
    duration = args.length
    output_dir = tempfile.mkdtemp()
    
    log.info('Traces saved to {}'.format(output_dir))

    # check to see if trace template exists
    template_path = pathlib.Path('./mde_tools/macOS_tracing/DefenderTracing.tracetemplate')
    if not template_path.exists:
        log.error('Cannot find trace template. Please download MDE Support tool again.')
        sys.exit(-1)

    # check if xctrace is installed
    has_xctrace = False
    if not run('xcode-select -p', verbose=False):
        log.info('Could not find xctrace, will fall back to log stream output')
        has_xctrace = False

    output_base_dir = ''
    if has_xctrace:
        trace_cmd = 'xcrun xctrace record --template {0} --all-processes --time-limit {1}s --output {2}/all_process.trace'.format(
            template_path, str(duration), output_dir).split()

        popen = subprocess.Popen(trace_cmd, stdout=subprocess.PIPE, universal_newlines=True, stderr=subprocess.PIPE, bufsize=1)
        for outline in popen.stdout:
            log.info(outline)

        output_base_dir = 'all_process.trace'
    else:
        predicate = r'( process == "wdavdaemon"  OR process == "wdavdaemon_enterprise" OR process == "wdavdaemon_unprivileged" ) AND (category == "DynamicTracing" OR category == "PointsOfInterest" )'
        trace_cmd = ['log','stream','--signpost','--style', 'compact']
        trace_cmd.append('--timeout')
        trace_cmd.append('{}s'.format(duration))
        trace_cmd.append('--predicate')
        trace_cmd.append(predicate)

        output_base_dir = 'log_traces'
        log_dir = os.path.join(output_dir, output_base_dir)
        os.makedirs(log_dir)
        with open( os.path.join(log_dir, 'trace.txt'), 'w', encoding='UTF-8') as trace_file:
            popen = subprocess.call(trace_cmd, stdout=trace_file, stderr=trace_file)
    
    archive_out_path = os.path.join(output_dir, 'all_process')
    archive_name = shutil.make_archive(archive_out_path, format='zip', root_dir=output_dir, base_dir=output_base_dir)
    return {'traces': [archive_name]}


def perf_trace(args):
    check_prerequisite()
    turn_on_tracing(args)

    trace_path = ''
    if os_details().platform == constants.MACOS_PLATFORM:
        trace_path = run_tracing_mac(args)
    turn_off_tracing()

    return trace_path
