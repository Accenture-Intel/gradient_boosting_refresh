import sh
import sys
import tempfile
import operator
import os
import json
import glob
import subprocess
import multiprocessing as mp
from pprint import pformat
import shutil
from functools import partial
import logging
from .constants import LOGGER_NAME
from .constants import XSLT_PERF_EPS_REPORT_PATH
from .report import XmlElement
from .utils import wait, run_with_output, run
from .mdatp import mdatp
from datetime import datetime
from lxml import etree
from collections import Counter, OrderedDict

log = logging.getLogger(LOGGER_NAME)

class PerfItem(json.JSONEncoder):
    def __init__(self, pid, cmdline, stdout=None, stderr=None):
        self.pid = pid
        self.cmdline = cmdline
        self.stdout = stdout or []
        self.stderr = stderr or []

    def append_to_stdout(self, line):
        self.stdout.append(line.strip())

    def append_to_stderr(self, line):
        self.stderr.append(line.strip())

    def default(self, o):
        return o.asdict()

    def asdict(self):
        return self.__dict__

    def __str__(self):
        return pformat(self.asdict())

    def __repr__(self):
        return str(self)

def _perf(pid, frequency, secs, base_dir):
    if not os.path.exists("/proc/{}".format(pid)):
        log.warning("can't process {} doesn't exist".format(pid))
        return

    dst = os.path.join(base_dir, "{}.data".format(pid))
    try:
        with open("/proc/{}/cmdline".format(pid)) as f:
            cmdline = f.read().replace("\x00", " ").strip()
    except Exception as e:
        raise IOError("unable to read process {} command line".format(pid)) from e

    try:
        item = PerfItem(pid=pid, cmdline=cmdline)
        sh.perf("record",
                "--pid", pid,
                "--output", dst,
                "--freq", frequency,
                "--",
                "sleep", secs,
                _out=item.append_to_stdout,
                _err=item.append_to_stderr)
        return item
    except Exception as e:
        raise IOError("Unable to capture perf data for pid: {}".format(pid)) from e

def create_package(base_dir, items):
    if len(items) > 0:
        with open(os.path.join(base_dir, "meta.json"), "w") as f:
            json.dump([x.asdict() for x in items], f)

    package_path = tempfile.mktemp(suffix=".tar.gz", prefix="mdatp_diag_", dir="/tmp")
    sh.tar("--create",
            "--gzip",
            "--file", package_path,
            "--directory", base_dir,
            ".")

    return package_path

class HotEventSources():
    def __init__(self, out_dir):
        self.command = mdatp.collect_hot_event_sources(None, True).split(' ')
        self.process = None
        self.out_dir = out_dir

    def __enter__(self):
        try:
            self.process = subprocess.Popen(self.command, stdout=subprocess.DEVNULL)
        except Exception as e:
            log.error(f'Exception during collecting hot event sources => [{e}]')

        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        if exc_type is not None:
            log.error(f'Exception during collecting hot event sources. Type => [{exc_type}], value => [{exc_value}]')
        else:
            self.stop()

    def stop(self):
        if self.process:
            self.process.kill()
            self.process.wait()

            files = glob.glob(os.path.join(os.getcwd(), 'hot_event_source_*.json'))
            if files:
                latest_file = max(files, key=os.path.getctime)
                shutil.move(latest_file, os.path.join(self.out_dir, 'hot_event_sources.txt'))
            self.process = None


def capture_on_linux(frequency, secs):
    base_dir = tempfile.mkdtemp(prefix="mdatp_diag_", dir="/tmp")
    perf_fn = partial(_perf,frequency=frequency, secs=secs, base_dir=base_dir)

    try:
        pids=sh.pidof("wdavdaemon").split()
        log.info("capturing Linux perf for pids: {}".format(pids))
        with mp.Pool(len(pids)) as p,  HotEventSources(base_dir) as hot_event_sources:
            processed = p.map(perf_fn, map(int,pids))
        log.info("creating compressed package...")
        package_path = create_package(base_dir, processed)
        log.info("compressed package created at: {}".format(package_path))
        return package_path
    except:
        log.debug("error while captureing Linux perf", exc_info=sys.exc_info())
    finally:
        log.debug("deleting intermidate files...")
        shutil.rmtree(base_dir)


def capture_macos_eps_events(base_dir, secs):
    try:
        log.info(f"  Collecting {secs}s epsext events")
        # step 1 enable debug log level
        log.debug("  turn on debug log level for mdatp")
        try:
            sh.log("config", "--mode", "persist:debug,level:debug", "--subsystem", "mdatp")
        except Exception as e:
            log.warn(f"unable to run log config to set debug level e: {e}")
            return

        log.debug(f"  wait for {secs} seconds.")
        beg_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with HotEventSources(base_dir) as hot_event_sources:
            wait(secs, "  waiting for eps events") # wait for os log system collect eps events
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.debug("  collecting eps event logs...")
        output = ""
        try:
            output = sh.log("show",
                    "--start", beg_time,
                    "--end", end_time,
                    "--predicate", 'subsystem == \"mdatp\" and category == \"macevents-epsext\"',
                    "--debug",
                    "--info",
                    _tty_out=False)
            output = "\n".join(output.splitlines())
        except Exception as e:
            log.warn(f"unable to run sh.log show e: {e}")
            return

        # dump event logs
        with open(os.path.join(base_dir, "eps_event.log"), "w") as f:
            f.write(f"start_time: {beg_time} end_time: {end_time}\n")
            f.write(output)

        # events statistics
        events = []
        for line in output.splitlines():
            line = line.split("] - ")[1:]
            if len(line) == 1:
                event = dict(map(str.strip, sub.split('=', 1)) for sub in line[0].split('|') if '=' in sub)
                if 'type' in event and 'seq' in event:
                    events.append(event)
                else:
                    log.debug("  invalid eps event!?")

        if len(events) <= 0:
            log.warn("did not find any valid eps event log.")
            return

        signing_ids_counter = Counter()
        pid_counter = Counter()
        type_counter = Counter()
        exe_counter = Counter()
        cdhash_counter = Counter()
        binary_dict = dict()

        for event in events:
            cs_id = event.get('cs_id', '')
            exe_path = event.get('exe', '')
            cdhash = event.get('cdhash', '')
            os_bin = event.get('os_bin', '')
            es_client = event.get('es_client', '')
            team_id = event.get('team_id', '')
            cs_flags = event.get('cs_flags', '')
            pid = event.get('pid', '')
            event_type = event.get('type', '')

            if len(cs_id) > 0:
                signing_ids_counter[cs_id] += 1

            if len(exe_path) > 0:
                exe_counter[exe_path] += 1

            if len(cdhash) > 0:
                cdhash_counter[cdhash] += 1

            if len(pid) > 0:
                pid_counter[pid] += 1

            if len(event_type) > 0:
                type_counter[event_type] += 1

            if len(exe_path) > 0:
                if exe_path not in binary_dict:
                    binary_dict[exe_path] = {
                        'app_id': cs_id,
                        'path': exe_path,
                        'cdhash' : cdhash,
                        'is_os_bin' : os_bin,
                        'is_es_client': es_client,
                        'team_id': team_id,
                        'cs_flags': cs_flags,
                        'pids': Counter({pid : 1})
                    }
                else:
                    binary_dict[exe_path]['pids'][pid] += 1

        signing_ids_counter = OrderedDict(signing_ids_counter.most_common())
        pid_counter = OrderedDict(pid_counter.most_common())
        type_counter =  OrderedDict(type_counter.most_common())
        exe_counter =  OrderedDict(exe_counter.most_common())
        cdhash_counter =  OrderedDict(cdhash_counter.most_common())

        xml_report_root = etree.Element('eps')
        xml_general = etree.SubElement(xml_report_root, 'general')
        xml_eventtypes = etree.SubElement(xml_report_root, 'eventtypes')
        xml_topnpid = etree.SubElement(xml_report_root, 'topnpid')
        xml_topnsid = etree.SubElement(xml_report_root, 'topnsid')
        xml_topnexe = etree.SubElement(xml_report_root, 'topnexe')
        xml_topncdhash = etree.SubElement(xml_report_root, 'topncdhash')
        xml_executables = etree.SubElement(xml_report_root, 'executables')

        XmlElement('start_time', beg_time).create_subelement_at(xml_general)
        XmlElement('finish_time', end_time).create_subelement_at(xml_general)
        XmlElement('event_count', len(events)).create_subelement_at(xml_general)

        for k in type_counter:
            type_name = f"unknown({k})"
            if k == "1":
                type_name = "auth"
            elif k == "2":
                type_name = "notify"
            XmlElement('type', attrs={'name': type_name, 'count': str(type_counter[k])}).create_subelement_at(xml_eventtypes)

        for k in signing_ids_counter:
            XmlElement('appid', attrs={'appid': k, 'count': str(signing_ids_counter[k])}).create_subelement_at(xml_topnsid)

        for k in exe_counter:
            XmlElement('exe', attrs={'path': k, 'count': str(exe_counter[k])}).create_subelement_at(xml_topnexe)

        for k in cdhash_counter:
            XmlElement('cdhash', attrs={'cdhash': k, 'count': str(cdhash_counter[k])}).create_subelement_at(xml_topncdhash)

        for k in pid_counter:
            command = ""
            try:
                lines=sh.ps("-o pid,command", "-w", "-p", f"{k}").splitlines()
                if len(lines) == 2 and k in lines[1]:
                    command = lines[1].strip().split(' ', 1)[1]
            except:
                log.debug("error sh.ps", exc_info=sys.exc_info())
            XmlElement('process', attrs={'pid': k, 'command': command,'count': str(pid_counter[k])}).create_subelement_at(xml_topnpid)

        for k in binary_dict:
            d = binary_dict[k]
            d['pids'] = json.dumps(OrderedDict(d['pids'].most_common()))
            XmlElement('executable', attrs=d).create_subelement_at(xml_executables)

        with open(os.path.join(base_dir, "eps_event_stat.html"), "wb") as f:
            xslt = etree.parse(XSLT_PERF_EPS_REPORT_PATH)
            f.write(etree.tostring(etree.XSLT(xslt)(xml_report_root), pretty_print=True))

    except:
        log.debug("error while captureing eps events", exc_info=sys.exc_info())
    finally:
        # last step turn off debug log level
        log.debug("  turn off debug log level for mdatp")
        try:
            sh.log("config", "--mode", "persist:default,level:default", "--subsystem", "mdatp")
        except Exception as e:
            log.warn(f"unable to run log config to restore log level e: {e}")
            return


def capture_on_macos(frequency, secs):
    base_dir = tempfile.mkdtemp(prefix="mdatp_diag_", dir="/tmp")

    try:
        capture_macos_eps_events(base_dir, secs)

        log.info("creating compressed package...")
        package_path = create_package(base_dir, [])
        log.info("compressed package created at: {}".format(package_path))
        return package_path
    except:
        log.debug("error while captureing macOS perf", exc_info=sys.exc_info())
    finally:
        log.debug("deleting intermidate files...")
        shutil.rmtree(base_dir)

