#!/usr/bin/python3
'''
IBM  "vpmem_hana_startup.py": A convenience script to recreate vPMEM or tmpfs
                              filesystems on boot if required.

This script
  - Scans a supplied configuration file to determine:
    - the parent UUID of the vPMEM volumes.
    - the HANA sid.
    - the parent directory under which to mount the vPMEM filesystems.
  - Searches the device tree to locate the vPMEM devices associated with the UUID.
    - For devices optimized for affinity (the expected case), multiple child
      volumes may be discovered.
  - Checkes if the devices have a valid file system on them.
    - If no valid file systems found, format them with an xfs filesystem.
  - Mounts each of the filesystems to a mount point representing their NUMA
    associativity.
  - Updates the HANA configuration file (global.ini) to reflect where the vPMEM
    devices are mounted for each NUMA domain.

Assumptions:
  - At least one vPMEM volume has been configured via the Power HMC.
  - vPMEM usage is already activated in the HANA ini scripts.
  - Default to xfs filesystems: -b 64k -s 512.

Dependencies:
  - /sbin/lsprop
  - /usr/bin/ndctl
  - /usr/bin/numactl

Installation (sample files can be found under https://github.com/IBM/vpmem-hana-startup):
  1. Choose a location for the script and config file
     (referred to as /mountpoint/path/to below).

  2. Create /mountpoint/path/to/vpmem_hana.cfg
    [
      {
        "sid"       : "<HANA instance name>"
        ,"nr"       : "<HANA instance number>"
        ,"hostname" : "<HANA hostname>"
        ,"puuid"    : "<parent vpmem volume uuid>"
        ,"mnt"      : "<filesystem path to mount vpmem filesystems under>"
      }
      {
        "sid"       : "<HANA instance name>"
        ,"nr"       : "<HANA instance number>"
        ,"hostname" : "<HANA hostname>"
        ,"mnt"      : "<filesystem path to mount tmpfs filesystems under>"
      }
    ]

  3. Create /etc/systemd/system/vpmem_hana.service taking care of NOTEs below
     [Unit]
     Description=Virtual PMEM SAP HANA Startup Script
     # NOTE: Ensure path to script is mounted. Replace /mountpoint as appropriate
     RequiresMountsFor=/mountpoint

     [Service]
     Type=oneshot
     # NOTE: Adjust the path to the startup script. Replace
     # /mountpoint/path/to as appropriate
     ExecStart=/bin/sh -c "/mountpoint/path/to/vpmem_hana_startup.py -c
                                /mountpoint/path/to/vpmem_hana.cfg -a -t
                                /mountpoint/path/to/vpmem_topology.sav"

     [Install]
     WantedBy=multi-user.target

  4. Start service now and on reboot
     systemctl start vpmem_hana.service
     systemctl status vpmem_hana.service
     systemctl enable vpmem_hana.service
'''

import getopt
import logging
import os
import re
import signal
import socket
import sys
import threading
import time
import json
import subprocess
import glob
from enum import IntEnum
import configparser

# Script usage:
USAGE = '''Usage: %s [-c <file>] [-t <file>] [-l <file>] [-s <size>] [-r] [-a] [-n] [-g] [-p] [-v] [-h]
 OPTIONS
 ============  =================================================================
 -c <file>     Full path configuration file.
 -t <file>     Full path topology file.
 -l <file>     Full path log file.
 -s <size>     Total memory size for tmpfs filesystems in KB, MB, GB or TB,
               e.g. 1024KB or 2048GB.
 -r            Recreate filesystem. This option forces recreation of the
               filesystem(s) regardless of whether valid or not.
 -a            Activate vPMEM usage in HANA ini files. Default: updates only
               mount point locations.
 -n            Filesystem numbering by index. Default is by NUMA node.
 -g            Record topology to file.
 -p            List volume parent UUIDs.
 -v            Print version.
 -h            Help.'''

# Constants used by the script:
VPMEM_SCRIPT_VERSION = "2.19"
PMEMSS_CMD_TIMEDOUT = "CMD_TIMEDOUT"
VPMEM_MAX_RETRIES = 3

# Absolute paths of tools needed by this script (verified during
# verifyDependencies()):
NDCTL_TOOL_PATH = "/usr/bin/ndctl"
BLKID_TOOL_PATH = "/sbin/blkid"
MKFS_TOOL_PATH = "/sbin/mkfs.xfs"
CAT_TOOL_PATH = "/usr/bin/cat"
LSPROP_TOOL_PATH = "/sbin/lsprop"
NUMACTL_TOOL_PATH = "/usr/bin/numactl"
UMOUNT_TOOL_PATH = "/usr/bin/umount"
DF_TOOL_PATH = "/usr/bin/df"
MKDIR_TOOL_PATH = "/usr/bin/mkdir"
MOUNT_TOOL_PATH = "/usr/bin/mount"
CHOWN_TOOL_PATH = "/usr/bin/chown"
CHMOD_TOOL_PATH = "/usr/bin/chmod"
MOUNTPOINT_TOOL_PATH = "/usr/bin/mountpoint"
RM_TOOL_PATH  = "/usr/bin/rm"

# Logger instance this script is using:
vpmemLogger = None

class TL(IntEnum):
    '''
    Trace level enums to make the trace level during the trace() calls more
    readable.
    '''
    ERROR = 0
    WARNING = 1
    INFO = 2
    DEBUG = 3
    CONSOLE = 2
    LEVEL = 9

# Global variables used by this script:

# Name of this script.
vpmemScriptName = ''

# Name of the Linux distribution this script is running on.
vpmemDistro = ''

# Path of the log file. If the '-l' option is not used the default path is:
#   /tmp/vpmem_hana_startup.<hostname>.log.
vpmemLogFilePath = ''

# Path of the configuration file specified by the '-c' option.
vpmemConfigFile = ''

# Path of the topology file specified by the '-t' option.
vpmemTopologyFile = ''

# Flag ('a' option) to control HANA usage of vPMEM via HANA ini files.
vpmemActivateUsage = False

# Flag ('r' option) to force recreation of the file systems.
vpmemRebuildFS = False

# Flag ('n' option) to numbering the file systems by index or by NUMA
# node ID (default).
vpmemFSSimpleNumbering = False

# Flag to store the topology to the file specified by the '-t' option.
vpmemRecordTopology = False

# Index used during numbering of the file systems when creating those and
# vpmemFSSimpleNumbering is True.
vpmemMntIndex = 0

# Dictionary used when creating the file systems containing the current index
# for file systems which do not belong to a specific NUMA node ("dot"-notation).
vpmemNUMANodeIdDict = {}

class PMEMSSDRFormatter(logging.Formatter):
    '''
    Derived Formatter to handle debug messages differently.
    '''
    def __init__(self, debug_fmt=None, fmt=None, datefmt=None):
        self.fmt = fmt or "%(message)s"
        self.dbg_fmt = debug_fmt or fmt

        logging.Formatter.__init__(self, self.fmt, datefmt)

    def format(self, record):
        tzt = divmod(-(time.altzone if (time.daylight and
            time.localtime().tm_isdst > 0) else time.timezone), 60)
        timezone = str.format("{0:+03d}{1:02d}", tzt[0] // 60, tzt[1])
        record.__dict__["timezone"] = timezone

        if record.levelno in [logging.DEBUG, logging.ERROR]:
            self._fmt = self.dbg_fmt
        else:
            self._fmt = self.fmt

        return logging.Formatter.format(self, record)

def initLogger(logFilePath):
    '''
    Initializing the logger used for this script. Default log file path is
    '/tmp/vpmem_hana_startup.<hostname>.log' otherwise specified by the user via
    the '-l' option.
    @param: logFilePath (str): Path to the log file.
    @return: logger (logger instance): The logger instance this script is using.
    '''

    # Create the directory the log file lives in case it does not exist.
    path, _ = os.path.split(logFilePath)
    if not os.path.isdir(path):
        os.mkdir(path)

    # Set the time stamp and log line formats
    isDSTActive = time.daylight and time.localtime().tm_isdst > 0
    utcOffsetSec = -time.altzone if isDSTActive else -time.timezone
    utcOffsetHours, utcOffsetMin = divmod(utcOffsetSec // 60, 60)
    timezone = "{0:+03d}{1:02d}".format(utcOffsetHours, utcOffsetMin)
    basicFormat = "%(asctime)s.%(msecs).3d%(timezone)5s: [%(levelname).1s] " \
        "%(threadName)-15s %(message)-50s"
    dateFormat = '%Y-%m-%d_%H:%M:%S'

    formatter = PMEMSSDRFormatter(fmt=basicFormat, datefmt=dateFormat)

    # Create the logger instance
    logger = logging.getLogger(vpmemScriptName)
    handler = logging.FileHandler(logFilePath)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    # the default permission is '0o644'
    os.chmod(logFilePath, 0o644)

    return logger

def trace(level, fmt, *args):
    '''
    Trace function used troughout the script. Trace level 0 and 1 will go to
    stdout and to the log file; all other trace levels only to the log file.
    @param: level (TL int enum): Trace level.
    @param: fmt (str): Format string.
    @param: *args (list): Variable list of arguments.
    @return: Nothing.
    '''
    if TL.CONSOLE >= level:
        prefix = ''
        if level == TL.ERROR:
            prefix = ' ERROR:'
        elif level == TL.WARNING:
            prefix = ' WARNING:'
        print('%s' % prefix, fmt % args)
        sys.stdout.flush()

    if TL.LEVEL >= level:
        if level == TL.ERROR:
            vpmemLogger.error(fmt, *args)
        elif level == TL.WARNING:
            vpmemLogger.warning(fmt, *args)
        elif level == TL.INFO:
            vpmemLogger.info(fmt, *args)
        else:       # TL.DEBUG
            vpmemLogger.debug(fmt, *args)

def _stop_process(proc, logCmd, timeout):
    '''
    When a command runs into a timeout the expired timer calls this function to
    print some meaningful message to the log file. In addition the function
    kills the timed out command  by sending a SIGTERM.
    '''
    try:
        if proc.poll() is None:
            trace(TL.DEBUG, "Command %s timed out after %s sec. Sending SIGTERM",
                  logCmd, timeout)
            os.kill(proc.pid, signal.SIGTERM)  # SIGKILL or SIGTERM

            time.sleep(0.5)
            if proc.poll() is None:
                trace(TL.DEBUG, "Command %s timed out after %s sec. Sending SIGKILL",
                      logCmd, timeout)
                os.kill(proc.pid, signal.SIGKILL)
    except Exception as err:
        vpmemLogger.exception(err)

def runCmd(args, timeout=42, sh=False, env=None, retry=0):
    '''
    Execute an external command, read the output and return it.
    @param args (str|list of str): Command to be executed.
    @param timeout (int): timeout in sec, after which the command is forcefully
                          terminated.
    @param sh (bool): True if the command is to be run in a shell and False if
                      directly. If the command contains arguments which must be
                      interpreted by a shell, e.g. wildcards this parameter must
                      be set to True.
    @param env (dict): Environment variables for the new process (instead of
                       inheriting from the current process).
    @param retry (int): Number of retries on command timeout.
    @return: (stdout, stderr, rc) (str, str, int): The output of the command.
    '''
    traceCmd = False

    if isinstance(args, str):
        logCmd = args
    else:
        logCmd = ' '.join(args)

    try:
        if env is not None:
            fullenv = dict(os.environ)
            fullenv.update(env)
            env = fullenv
        if sh:
            cmd = ' '.join(args)
        else:
            cmd = args
        # create the subprocess, ensuring a new process group is spawned
        # so we can later kill the process and all its child processes
        proc = subprocess.Popen(cmd, shell=sh,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                close_fds=False, env=env)

        timer = threading.Timer(timeout, _stop_process, [proc, logCmd, timeout])
        timer.start()

        (sout, serr) = proc.communicate()
        timer.cancel()  # stop the timer when we got data from process

        ret = proc.poll()
    except OSError as err:
        trace(TL.DEBUG, "%s", str(err))
        sout = ""
        serr = str(err)
        ret = 127 if "No such file" in serr else 255
    finally:
        try:
            proc.stdout.close()
            proc.stderr.close()
        except:  #pylint: disable=bare-except
            pass

    timeout = ret in (-signal.SIGTERM, -signal.SIGKILL)  # 143,137
    if ret == -6 and retry >= 0 :  # special handling for sigAbrt
        trace(TL.DEBUG, "retry abrt %s", args)
        (sout, serr, ret) = runCmd(args, timeout, sh, env, -1)

    if timeout and retry > 0:
        retry -= 1
        trace(TL.DEBUG, "Retry command %s counter: %s", args, retry)
        (sout, serr, ret) = runCmd(args, timeout, sh, env, retry)
    elif timeout:
        serr = PMEMSS_CMD_TIMEDOUT
        trace(TL.DEBUG, "runCMD: '%s' Timeout:%d ret:%s", args, timeout, ret)
    elif traceCmd:
        trace(TL.DEBUG, "runCMD: '%s' Timeout:%d ret:%s \n%s \n%s", args, timeout,
              ret, serr, sout)

    if not ret:
        trace(TL.DEBUG, "Run cmd '%s' succeed (ret 0): \n%s\n", args, sout)
    else:
        trace(TL.DEBUG, "Run cmd '%s' failed (ret %d): \n%s\n", args, ret, serr)
    return (sout.decode(), serr.decode(), ret)

def runCmdExitOnError(args, timeout=42, sh=False, env=None, retry=0):
    '''
    Short form of runCmd(). It takes the same parameters as runCmd() but it
    exits immediatly in case runCmd() returned with a error.
    @param args (str|list of str): Command to be executed.
    @param timeout (int): timeout in sec, after which the command is forcefully
                          terminated.
    @param sh (bool): True if the command is to be run in a shell and False if
                      directly. If the command contains arguments which must be
                      interpreted by a shell, e.g. wildcards this parameter must
                      be set to True.
    @param env (dict): Environment variables for the new process (instead of
                       inheriting from the current process).
    @param retry (int): Number of retries on command timeout.
    @return: Nothing.
    '''
    _, _, ret = runCmd(args, timeout, sh, env, retry)
    if ret != 0:
        errStr = "Command " + str(args) + " failed (rc " + str(ret) + ")."
        epilogAndExit(errStr, ret)

def epilogAndExit(epilog, exitCode, printUsage=False):
    '''
    Helper function to print an epilog and exit.
    @param epilog (str): String to be printed.
    @param exitCode (int): Exit code this script ends with.
    @param printUsage (bool): True: Print script usage to stderr. False: Print
                      epilog to stdout and to the log file with an additional
                      hint to the written log file in case the exit code is not
                      zero.
    @return: exitCode (int): Exit code to the caller of this scriopt.
    '''
    if not printUsage:
        if exitCode:
            trace(TL.INFO, "%s See log file %s for more details.", epilog,
                  vpmemLogFilePath)
        elif len(epilog) > 0:
            trace(TL.INFO, "%s", epilog)
    else:
        sys.stderr.write(epilog + "\n")
        sys.stderr.write(USAGE % sys.argv[0] + "\n")
    sys.exit(exitCode)

def unmountCmd(path, loop=False, printErr=True):
    '''
    Unmount specified file system.
    @param: path (str): The path of the file system to unmount.
    @param: loop (bool): Flag, to decide if the unmount command should run in a
            loop until VPMEM_MAX_RETRIES reached.
    @param: printErr (bool): Suppress error message on stdout.
    @return: (bool): True if the unmount succeeds otherwise False.
    '''
    if not os.path.exists(path):
        trace(TL.ERROR, "Path %s does not exist", path)
        return False

    failed = 0
    while True:
        cmd = [UMOUNT_TOOL_PATH, '-f', path]
        _, serr, ret = runCmd(cmd)
        if ret == 0:
            trace(TL.DEBUG, "Unmounted %s successfully", path)
            return True
        failed += 1
        if printErr:
            trace(TL.ERROR, "Unmounting %s failed (rc: %d serr: %s)",
                  path, ret, serr)
        if loop:
            time.sleep(1)
        if not loop or failed == VPMEM_MAX_RETRIES:
            break

    return False

def naturalSort(listToSort):
    '''
    Natural sort function.
    @param: listToSort (list): List to sort.
    @return: (list): Natural sorted list.
    '''
    def convert(text):
        # Convert text to lower case for further sort processing.
        return int(text) if text.isdigit() else text.lower()
    def getAlphanumKey(text):
        return [convert(c) for c in re.split('([0-9]+)', text)]
    if len(listToSort) == 0:
        return listToSort
    return sorted(listToSort, key=getAlphanumKey)

def getTotalMemory():
    '''
    Return the total amount of memory in kB. This is used when creating tmpfs
    volumes to calculate the size of tmpfs volumes.
    @return: memTotalkB (int): Total memory in kB.
    '''
    memTotalkB = 0
    with open('/proc/meminfo', encoding="utf-8") as fh:
        memInfo = fh.read()
    match = re.search(r'^MemTotal:\s+(\d+)', memInfo)
    if match:
        memTotalkB = int(match.groups()[0])
    trace(TL.DEBUG, "Total memory: %d kB", memTotalkB)
    return memTotalkB

def verifyDependencies():
    '''
    Verify that the installed Python version matches (here: major version 3 or
    newer) and that various utilities we need (lsprop, ndctl, ...) are available.
    @param: None.
    @return: bool: False if the verification steps fail otherwise True.
    '''
    trace(TL.DEBUG, "Used Python version: '%s'", sys.version)
    if sys.version_info.major < 3:
        trace(TL.ERROR, "Python version 3 or newer required, but found Python "
              "version %d.%d.", sys.version_info.major, sys.version_info.minor)
        return False
    for toolPath in (NDCTL_TOOL_PATH, BLKID_TOOL_PATH, MKFS_TOOL_PATH,
                     CAT_TOOL_PATH, LSPROP_TOOL_PATH, NUMACTL_TOOL_PATH,
                     UMOUNT_TOOL_PATH, DF_TOOL_PATH, MKDIR_TOOL_PATH,
                     MOUNT_TOOL_PATH, CHOWN_TOOL_PATH, CHMOD_TOOL_PATH,
                     MOUNTPOINT_TOOL_PATH, RM_TOOL_PATH):
        if not os.path.isfile(toolPath):
            trace(TL.ERROR, "Required dependency %s not found", toolPath)
            return False
    return True

def verifyJSON(jsonFilePath):
    '''
    Verify if the specified file contains a valid JSON structure.
    @param: jsonFilePath (str): Path to the JSON based file.
    @return: bool: False if the verification step fail otherwise True.
    '''
    with open(jsonFilePath, encoding="utf-8") as fh:
        try:
            json.load(fh)
        except ValueError as err:
            trace(TL.ERROR, "%s is not a valid JSON file (err %s).",
                  jsonFilePath, err)
            return False
    return True

def verifyPermissions():
    '''
    Verify that this script runs as root.
    @param: None.
    @return: bool: False if the verification step fail otherwise True.
    '''
    if not os.geteuid() == 0:
        trace(TL.ERROR, "This script must be run as root.")
        return False
    else:
        return True

def getValueFromFileWithKeyAndDelimiter(filePath, delimiter, key):
    '''
    Extracts a value from a flat file of the structure <KEY><DELIMITER><VALUE>,
    e.g. PRETTY_NAME="SUSE Linux Enterprise Server 15 SP4"
    @param: filePath (str): Path to the file.
    @param: delimiter (str): Delimiter between key and value.
    @param: key (str): The key for which the value should be returned.
    @return: Tuple of (bool, str): True: The returned string is the value for
             the specified key. False: The key was not found in the file and the
             string 'UNKNOWN' will be returned as value.
    '''
    myDict = {}
    with open(filePath, encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            k, v = line.rstrip().split(delimiter)
            myDict[k] = v.strip('"')

    if key not in myDict:
        return (False, 'UNKNOWN')
    else:
        return (True, myDict[key])

def verifyAndGetCfgInfo(cfgDict, cfgFilePath):
    '''
    Verify the configuration values from the passed-in dictionary. The following
    configuration values will be verified from the dictionary:
        "sid"      : "<HANA instance name>"
        "nr"       : "<HANA instance number>"
        "mnt"      : "<filesystem path to mount vpmem filesystems under>"
    If one of them did not exist the script returns immediatly with an error
    (False), which means the current configuration is invalid.
        "puuid"    : ""
    If the puuid does not exist in the configuration file it is assumed that the
    file system type if 'tmpfs' otherwise 'vpmem'.
        "hostname" : "<hostname of the host HANA is installed on>"
    If the hostname does not exist in the configuration file this function
    extracts it from the OS via a socket system call.
    @param: cfgDict (dict): Dictionary containing the configuration.
    @param: cfgFilePath (str): Path to the configuration file.
    @return: Tuple of (bool, dict): False, if an error occurred. In this case
             the returned dictionary cannot be used. True, if the verification
             succeed and the dictionary with the configuration values consisting
             of key-value tuples.
    '''
    trace(TL.INFO, "Verifying configuration parameters in %s.", cfgFilePath)

    if "sid" not in cfgDict:
        trace(TL.ERROR, "SID not specified in configuration file. Keyword: "
              "'sid'")
        return (False, cfgDict)
    if "nr" not in cfgDict:
        trace(TL.ERROR, "Instance number not specified in configuration file. "
              "Keyword: 'nr'")
        return (False, cfgDict)
    if "mnt" not in cfgDict:
        trace(TL.ERROR, "Filesystem mountpoint not specified in configuration "
              "file. Keyword: 'mnt'")
        return (False, cfgDict)

    # Get the sid and convert it to upper and lower case for later use
    sid = cfgDict.get("sid")
    cfgDict["siduc"] = sid.upper()
    cfgDict["sidlc"] = sid.lower()

    puuids = cfgDict.get("puuid")
    if puuids is not None:
        # Convert a single puuid string into a list of puuids for further
        # processing.
        if isinstance(puuids, str):
            puuids = [puuids]
            cfgDict["puuid"] = puuids
        for puuid in puuids:
            if (len(puuid) != 36 or
                not re.match(r"[A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-" \
                              "[A-F0-9a-f]{4}-[A-F0-9a-f]{12}\}?$", puuid)):
                trace(TL.ERROR, "Invalid UUID specified: '%s'.", puuid)
                return (False, cfgDict)
            trace(TL.INFO, "Valid UUID found: '%s'.", puuid)
        trace(TL.INFO, "Config parameter (puuid): UUID=%s", puuids)
        cfgDict['type'] = "vpmem"
    else:
        cfgDict['type'] = "tmpfs"

    # Accept 'host' as well as 'hostname' key for hostname configuration entry.
    # In case both do not exist in the configuration file get it via the socket
    # modul.
    if cfgDict.get("host") is None:
        if cfgDict.get("hostname") is None:
            trace(TL.DEBUG, "Hostname not specified in script configuration "
                  "file. Keyword: 'host' or 'hostname'. Evaluating via OS.")
            cfgDict['hostname'] = socket.gethostname().split('.')[0]
    else:
        cfgDict['hostname'] = cfgDict.pop('host') # Rename key to 'hostname'

    trace(TL.INFO, "Config parameter (sid): HANA SID=%s", cfgDict.get("sid"))
    trace(TL.INFO, "Config parameter (nr): HANA instance no=%s", cfgDict.get("nr"))
    trace(TL.INFO, "Config parameter (mnt): Mount point=%s", cfgDict.get("mnt"))
    trace(TL.INFO, "Config parameter (host OR hostname): Hostname=%s", cfgDict.get("hostname"))
    trace(TL.INFO, "Config parameter (type): File system type=%s", cfgDict.get("type"))

    return (True, cfgDict)

def convertMemorySizeToKB(memSize):
    '''
    Converts memory size into KB.
    @param: memSize (str): Memory size to be converted.
    @return: memSizeInKB (int): Converted memory size in KB.
    '''
    units = {"KB": 1, "MB": 2**10, "GB": 2**20, "TB": 2**30}

    memSizeUC = memSize.strip().upper()
    memSizeInKB = 0
    if not re.match(r' ', memSizeUC):
        memSizeUC = re.sub(r'([KMGT]?B)', r' \1', memSizeUC)
    (number, unit) = [str.strip() for str in memSizeUC.split()]
    memSizeInKB = int(float(number) * units[unit])
    trace(TL.DEBUG, "Converted '%s' to %d kB.", memSizeUC, memSizeInKB)
    return memSizeInKB

def calcTmpFSMemSizes(totalMemSizeReq, NUMANodeList):
    '''
    Verify the specfied total tmpfs memory size and calculate the portions of
    tmpfs volume sizes based on the number of NUMA node and the total memory
    size available for every single NUMA node.
    @param: totalMemSizeReq (str): Total tmpfs memory size specified by the
            caller of this script by using the '-s' option.
    @param: NUMANodeList (list): List of NUMA node Ids used to evaluate the
            total memory size for every single NUMA node.
    @return: tuple of (valid, memSizePerNUMANodeDict) (bool, dict): valid is
             True if the passed-in totalMemSize is valid and all sanity checks
             succeeded otherwise False. In case valid is True
             memSizePerNUMANodeDict contains for every single NUMA node its
             memory size in KB otherwise an empty dictionary. The sum of all
             memory sizes in this dictionary is equal totalMemSizeReq. The
             partial memory sizes will be calculated based on the total memory
             available for every single NUMA node.
    '''
    memSizePerNUMANodeDict = {}
    # Empty string means the caller of this script did not specify the total
    # tmpfs memory size; just return.
    if not totalMemSizeReq:
        return (True, memSizePerNUMANodeDict)

    # Is the specified size starting with a digit?
    if not totalMemSizeReq.strip()[0].isdigit():
        trace(TL.ERROR, "Invalid format of memory size: '%s' expected: "
              "<INTEGER>KB/MB/TB", totalMemSizeReq)
        return (False, memSizePerNUMANodeDict)

    totalMemSizekB = getTotalMemory()
    totalMemSizeReqkB = convertMemorySizeToKB(totalMemSizeReq)

    if totalMemSizeReqkB >= totalMemSizekB:
        trace(TL.ERROR, "Total memory size requested (%d kB) for tmpfs "
              "equal or greater total memory available (%d kB).",
              totalMemSizeReqkB, totalMemSizekB)
        return (False, memSizePerNUMANodeDict)

    # Print a warning, if the requested memory size is greater/equal 90% of the
    # total memory size configured for the LPAR to give the caller a hint that
    # the requested tmpfs size is close to the total memory size.
    if totalMemSizeReqkB >= round(0.9 * totalMemSizekB):
        trace(TL.WARNING, "Total memory size requested (%d kB) for tmpfs "
              "reaches 90%% of the total memory available (%d kB).",
              totalMemSizeReqkB, totalMemSizekB)

    trace(TL.DEBUG, "Parse and verify memory size: totalMemSize (kB): %d "
          "totalMemSizeReq (kB): %d, NUMA node list: %s", totalMemSizekB,
          totalMemSizeReqkB, NUMANodeList)

    # Get the total memory size of every NUMA node.
    cmd = [NUMACTL_TOOL_PATH, '-H']
    sout, _, ret = runCmd(cmd)
    if len(sout) == 0 or ret != 0:
        trace(TL.ERROR, "%s failed (rc: %d).", cmd, ret)
        return (False, memSizePerNUMANodeDict)
    regex = r'node (\d+) size: (\d+) (\w+)'
    matches = re.findall(regex, sout)
    if not matches:
        trace(TL.ERROR, "Unexpected output returned by %s.", cmd)
        return (False, memSizePerNUMANodeDict)
    totalMemDictPerNUMA = dict((nodeId, (totalMem, suffix))
                                for (nodeId, totalMem, suffix) in matches)
    # Iterate over all NUMA nodes and calculate the memory size fraction for
    # this node based on the total memory for this node.
    sumMemSizeAllNUMANodes = 0
    for nodeId in NUMANodeList:
        if nodeId not in totalMemDictPerNUMA.keys():
            trace(TL.ERROR, "NUMA node 'node%s' not in output of %s listed.",
                  nodeId, cmd)
            return (False, memSizePerNUMANodeDict)
        totalMemSizePerNUMAkB = convertMemorySizeToKB(totalMemDictPerNUMA[nodeId][0] +
                                                      totalMemDictPerNUMA[nodeId][1])
        memSizeReqPerNUMAkB = round((float(totalMemSizePerNUMAkB / totalMemSizekB)) *
              totalMemSizeReqkB)
        trace(TL.DEBUG, "NUMA node: %s total memory size: %s kB size tmpfs "
              "for this node: %d kB", nodeId, totalMemSizePerNUMAkB,
              memSizeReqPerNUMAkB)
        memSizePerNUMANodeDict[nodeId] = str(memSizeReqPerNUMAkB)
        sumMemSizeAllNUMANodes += memSizeReqPerNUMAkB

    trace(TL.DEBUG, "totalMemSizeReq (kB): %d, sumMemSizeAllNUMANodes (kB): %d "
          "diff (kB): %d", totalMemSizeReqkB, sumMemSizeAllNUMANodes,
          (totalMemSizeReqkB - sumMemSizeAllNUMANodes))

    return (True, memSizePerNUMANodeDict)

def listFileSystemSummary(sid, fileSystemList, NUMANodeList):
    '''
    Print a summary for the vPMEM file systems by using the Linux df command.
    @param: sid (str): The HANA instance ID the vPMEM volumes belong to.
    @param: fileSystemList (list): List of file system volumes to print.
    @param: NUMANodeList (list): List of NUMA node Ids.
    @return: (bool): Always True
    '''
    trace(TL.DEBUG, "List vPMEM summary enter; SID: %s file system list: %s "
          "NUMA node list: %s", sid, fileSystemList, NUMANodeList)
    if len(fileSystemList) == 0:
        trace(TL.INFO, "No file system volume(s) defined.")
        return True

    if len(fileSystemList) != len(NUMANodeList):
        trace(TL.ERROR, "Error: NUMA node and file system list are of unequal "
              "length. Dubious results.")
    else:
        trace(TL.INFO, "File system summary:\n")
        # Print header
        print("Instance: %3s" % sid)
        print("%4s %9s %9s %9s %s" % ("Numa", "", "", "Percent", ""))
        print("%4s %9s %9s %9s %s" % ("Node", "Available", "Used", "Used",
                                      "Mountpoint"))
        print("%4s %9s %9s %9s %s" % ("----", "---------", "---------",
                                      "---------",
                                      "------------------------------------"))
        # Get and print file system disk space usage
        for fs, nn in zip(fileSystemList, NUMANodeList):
            cmd = [DF_TOOL_PATH, '-h', '--output=avail,used,pcent', fs]
            sout, _, ret = runCmd(cmd)
            if len(sout) > 0 and ret == 0:
                # The df command returns something like:
                #   Avail   Used Use%
                #    498G  1015M   1%
                # hence, skip the header of df output by getting just the 2nd
                # line.
                for line in sout.split('\n'):
                    if line.strip().lower().startswith("avail") or \
                       len(line.strip()) == 0:
                        continue
                    (avail, used, pcent) = line.strip().split()
                    print("%4s %9s %9s %9s %s" % (nn, avail, used, pcent, fs))
        print("\n") # Nicer output
    return True

def listPUUIDs():
    '''
    Print a list of PUUID's to stdout by using the lsprop command in combination
    with a regular expression.
    The regular expression extracts the region AND the PUUID from the output
    returned by the lsprop command.
    Example for the region substring: 'region123'
    Example for the PUUID substring:  '4d1c54f4-1a75-4e4c-817e-bdb65222c601'
    '''
    regex = r"region[0-9]+|[A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-" \
             "[A-F0-9a-f]{4}-[A-F0-9a-f]{12}"
    # Command must run in a shell, because the command list contains wildcards
    # which must be interpreted by a shell
    cmd = [LSPROP_TOOL_PATH, '/sys/devices/ndbus*/region*/of_node/ibm,unit-parent-guid']
    sout, _, ret = runCmd(cmd, sh=True)
    if ret == 0:
        if len(sout) > 0:
            matches = re.findall(regex, sout)
            # Print header
            print("%10s %4s %13s %s" % ("vPMEM ", "Numa", "", ""))
            print("%10s %4s %13s %s" % ("Region ", "Node", "Size", "Parent UUID"))
            print("%10s %4s %13s %s" % ("----------", "----", "-------------",
                                        "------------------------------------"))
            # Convert list into dictionary for further processing
            regionDict = dict(map(lambda i: (matches[i], matches[i+1]),
                                range(len(matches)-1)[::2]))
            sortedKeys = naturalSort(regionDict.keys())
            for region in sortedKeys:
                puuid = regionDict[region]
                cmd = [CAT_TOOL_PATH, '/sys/devices/ndbus*/' + region + '/size']
                sout, _, ret = runCmd(cmd, sh=True)
                if len(sout) > 0 and ret == 0:
                    size = sout.strip()
                cmd = [CAT_TOOL_PATH, '/sys/devices/ndbus*/' + region + '/numa_node']
                sout, _, ret = runCmd(cmd, sh=True)
                if len(sout) > 0 and ret == 0:
                    numanode = sout.strip()
                print("%10s %4s %13s %s" % (region, numanode, size, puuid))
        else:
            trace(TL.INFO, "No volume parent UUIDs found.")
    return True

def getTmpFSMnts(mntParent, sid):
    '''
    Prints the tmp file system volumes to stdout by using the /proc/mounts
    entries.
    @param: mntParent (str): Base mount point.
    @param: sid (str): HANA instance ID the tmpfs volumes belong to.
    @return: myFileSystemList (list): List of tmpfs file systems identified by
             this function.
    '''
    myFileSystemList = []
    myNUMANodeList = []
    trace(TL.DEBUG, "Get tmpfs mounts enter; SID: %s mount parent: %s", sid, mntParent)

    printedHeader = False
    mntParent = mntParent + '/' + sid.upper()
    mounts = None
    with open('/proc/mounts','r', encoding="utf-8") as file:
        mounts = [line.split() for line in file.readlines()]

    for mount in mounts:
        if len(mount) < 6 or not mount[1].startswith(mntParent) or \
           mount[2] != 'tmpfs' or sid not in mount[1]:
            continue

        if not printedHeader:
            trace(TL.INFO, "Following existing tmpfs file systems have been found:\n")
            print("Name         Mountpoint                                       "
                "Type     Options                                                   Node")
            print("------------ ------------------------------------------------ "
                "-------- --------------------------------------------------------- ----")
            printedHeader = True

        (mntname, mntpoint, mnttype, mntopts, _, _) = mount[:]
        node = ''
        if "prefer" in mntopts:
            match = re.search(r'prefer:(\d+)', mntopts) # Extracting the node
            if match:
                node = match.group(1)
            print(' '.join([mntname.rjust(12), mntpoint.rjust(48),
                            mnttype.rjust(8), mntopts.rjust(57), node.rjust(4)]))

        myFileSystemList.append(mntpoint)
        myNUMANodeList.append(node)

    myFileSystemList = naturalSort(myFileSystemList)

    if not myFileSystemList:
        trace(TL.INFO, "No tmpfs file system found.")
    else:
        print("\n") # Nicer output

    trace(TL.DEBUG, "Get tmpfs mounts exit; file system list: %s NUMA node list: %s",
          myFileSystemList, myNUMANodeList)

    return myFileSystemList

def getNUMANodes(recordTopology, topologyFilePath):
    ''' Extracts the NUMA node Id's from the sys file system and puts them into
        a list for further processing. The functions returns two lists, current
        found NUMA nodes and the previous list of NUMA nodes. If recordTopology
        is True the extracted NUMA node Id's will be stored in the file
        specified by topologyFilePath.
        @param: recordTopology (bool): Flag to store the extracted NUMA topology
                to a file.
        @param: topologyFilePath (str): Path to file to which the NUMA topology
                will be stored in case recordTopology is True. When
                recordTopology is False prevNUMANodeIds will contain the
                (previous) NUMA node IDs read from the this topolopy file.
        @return: Tuple of curNUMANodeIds (list): List of current NUMA node IDs
                 and prevNUMANodeIds (list): List of previous NUMA node IDs in
                 case the topologyFilePath exists and recordTopology is False.
    '''
    curNUMANodeIds = []
    prevNUMANodeIds = []

    trace(TL.INFO, "Extracting NUMA nodes.")

    SYS_PATH = "/sys/devices/system/node/node"
    regEx = r"" + SYS_PATH + "(\d+)"
    for nodepath in glob.glob(SYS_PATH + '*'):
        match = re.findall(regEx, nodepath)
        cmd = ['compgen', '-G',  nodepath + '/memory*']
        # Command must run in a shell, because compgen is a shell buildin cmd
        _, _, ret = runCmd(cmd, sh=True)
        if len(match) and ret == 0:
            trace(TL.DEBUG, "Found NUMA node with id=%s (rc: %d)", match[0], ret)
            curNUMANodeIds.append(match[0])

    if len(curNUMANodeIds) > 0:
        curNUMANodeIds = naturalSort(curNUMANodeIds)
        trace(TL.INFO, "Found %d NUMA nodes.", len(curNUMANodeIds))

    if recordTopology:
        trace(TL.INFO, "Writing %d NUMA node IDs to %s.",
                len(curNUMANodeIds), topologyFilePath)
        trace(TL.DEBUG, "NUMA node IDs: %s", curNUMANodeIds)
        with open(topologyFilePath, 'w', encoding="utf-8") as file:
            file.write(' '.join(curNUMANodeIds) + '\n')
    else:
        if (len(topologyFilePath) and os.path.exists(topologyFilePath)):
            with open(topologyFilePath, 'r', encoding="utf-8") as file:
                lines = file.readlines()
            for line in lines:
                numaNodeList = line.rstrip().split(' ')
                prevNUMANodeIds.extend(numaNodeList)

            prevNUMANodeIds = naturalSort(prevNUMANodeIds)
            trace(TL.DEBUG, "Previous NUMA node list: %s read from: %s",
                  prevNUMANodeIds, topologyFilePath)

    trace(TL.DEBUG, "Found %d NUMA nodes with id(s): %s", len(curNUMANodeIds),
          str(curNUMANodeIds))

    return (curNUMANodeIds, prevNUMANodeIds)

def removeTmpfsAllMnts(fileSystemList):
    '''
    Remove all tmpfs file systems by using the Linux umount command.
    @param: fileSystemList (list): List of tmpfs file systems to be removed.
    @return: True
    '''
    trace(TL.DEBUG, "Remove tmpfs mounts enter; file system list: %s",
          fileSystemList)

    failed = 0
    for fs in fileSystemList:
        if not unmountCmd(fs):
            failed += 1

    trace(TL.DEBUG, "Unmounted tmpfs; succeeded: %d failed: %d",
          (len(fileSystemList) - failed), failed)

    trace(TL.INFO, "Removed %d tmpfs file systems.",
          len(fileSystemList) - failed)

    return True

def createTmpFSMounts(sid, mntparent, numaNodes, memSizePerNUMANode):
    '''
    Create tmpfs file systems by using the Linux commands:
        -mkdir: to create the mount point the tmpfs volume lives
        -mount: to create the tmpfs volume
        -chown: to set the owner to the tmpfs volume
        -chmod: to set the permissions for the tmpfs volume
    In case one of these commands fail the script returns immediatly with an
    error and exits (with on exit code) otherwise it adds the created tmpfs file
    system to myFileSystemList which will be returned at the end.
    @param: sid (str): HANA instance ID the tmpfs file systems created for.
    @param: mntparent (str): Base path for the mount point.
    @param: numaNodes (list): List of NUMA node IDs the tmpfs file system
            volumes belong to.
    @param: memSizePerNUMANode (dict): Memory size for tmpfs volumes of every
            single NUMA node in kB.
    @return: myFileSystemList (list): List of tmpfs file systems created by this
             function.
    '''
    trace(TL.DEBUG, "Create tmpfs mounts SID: %s mount parent: %s NUMA nodes: %s",
          sid, mntparent, numaNodes)

    myFileSystemList = []
    if not sid or not mntparent or not numaNodes:
        trace(TL.ERROR, "HANA SID or mount point or NUMA node list empty.")
        return myFileSystemList

    siduc = sid.upper()
    sidlc = sid.lower()
    basePath = mntparent + '/' + siduc + '/' + "node"
    # Split the default size of tmpfs (50%) accross all NUMA nodes to avoid
    # overbooking the memory by tmpfs when not using the size option.
    if not memSizePerNUMANode:
        memTotalkB = getTotalMemory()
        sizeOpt = str(round((memTotalkB/2)/len(numaNodes))) + 'k'
        trace(TL.DEBUG, "Size for tmpfs volume(s): %sB", sizeOpt)
    # ATTENTION: numaNodes must be an array of grouped digits
    for nodeId in numaNodes:
        fs = basePath + nodeId
        if memSizePerNUMANode:
            sizeOpt = memSizePerNUMANode[nodeId] + 'k'
            trace(TL.DEBUG, "Size for tmpfs volume for NUMA node %s: %sB",
                  nodeId, sizeOpt)

        cmd = [MKDIR_TOOL_PATH, '-p', fs]
        runCmdExitOnError(cmd)

        cmd = [MOUNT_TOOL_PATH, 'tmpfs' + siduc + nodeId, '-t', 'tmpfs', '-o',
               'mpol=prefer:' + nodeId + ',' + 'size=' + sizeOpt, fs]
        runCmdExitOnError(cmd)

        cmd = [CHOWN_TOOL_PATH, '-R', sidlc + 'adm:sapsys', fs]
        runCmdExitOnError(cmd)

        cmd = [CHMOD_TOOL_PATH, '777', '-R', fs]
        runCmdExitOnError(cmd)

        myFileSystemList.append(fs)

    myFileSystemList = naturalSort(myFileSystemList)

    trace(TL.INFO, "Created %d tmpfs file systems.", len(myFileSystemList))

    return myFileSystemList

def getRegionsByUuid(uuid):
    '''
    Extracting the regions found for the passed-in UUID by reading from the sys
    file system with the lsprop command.
    @param: uuid (str): The UUID for which the regions should be extracted.
    @return: regions (list): A natural sorted list of regions found for the
             specified UUID.
    '''
    trace(TL.INFO, "Getting regions for UUID: %s.", uuid)

    regions = []
    # regex to find the region AND the PUUID of the output returned by the lsprop
    # command.
    # Example for the region substring: 'region123'
    # Example for the PUUID substring: '4d1c54f4-1a75-4e4c-817e-bdb65222c601'
    regex = r"region[0-9]+|[A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-" \
             "[A-F0-9a-f]{4}-[A-F0-9a-f]{12}"
    # Command must run in a shell, because the command list contains wildcards
    # which must be interpreted by a shell
    cmd = [LSPROP_TOOL_PATH, '/sys/devices/ndbus*/region*/of_node/ibm,unit-parent-guid']
    sout, _, ret = runCmd(cmd, sh=True)
    if len(sout) > 0 and ret == 0:
        matches = re.findall(regex, sout)
        # Use zip to get pairwise tuples
        for _region, _uuid in zip(matches[::2], matches[1::2]):
            if uuid == _uuid:
                regions.append(_region)
        if len(regions) > 0:
            regions = naturalSort(regions)
            trace(TL.INFO, "%d regions found for UUID: %s.", len(regions), uuid)
            trace(TL.DEBUG, "Regions found: %s", regions)
        else:
            trace(TL.ERROR, "No regions found for UUID: %s.", uuid)
    return regions

def validateNamespace(region):
    '''
    Verify and create the namespaces for the specified region by using the ndctl
    command. If one of the ndctl attempts fails the script will exit immediatly.
    @param: region (str): Region for which the ndctl returns all attached
            devices along with some of their major attributes.
    @return: True, in case all ndctl attempts succeed.
    '''
    trace(TL.INFO, "Validating namespace for region: %s.", region)

    cmd = [NDCTL_TOOL_PATH, 'list', '-N', '-r', region]
    sout, _, ret = runCmd(cmd)
    # If the 'ndctl list' subcommand returns nothing (aka sout is empty)
    # creating the namespaces
    if len(sout) == 0 and ret == 0:
        trace(TL.DEBUG, "Create namespace for region: %s", region)
        # Extracting the number from region
        match = re.search(r'region(\d+)', region)
        if match:
            rno = match.group(1)
            cmd = [NDCTL_TOOL_PATH, 'disable-region', 'region' + rno]
            runCmdExitOnError(cmd)
            cmd = [NDCTL_TOOL_PATH, 'zero-labels', 'nmem' + rno]
            runCmdExitOnError(cmd)
            cmd = [NDCTL_TOOL_PATH, 'init-labels', 'nmem' + rno]
            runCmdExitOnError(cmd)
            cmd = [NDCTL_TOOL_PATH, 'enable-region', 'region' + rno]
            runCmdExitOnError(cmd)
            cmd = [NDCTL_TOOL_PATH, 'create-namespace', '-m', 'fsdax', '-r', 'region' + rno]
            runCmdExitOnError(cmd)
    elif ret != 0:
        trace(TL.ERROR, "Validating namespace for region: %s failed.", region)
        return False

    return True

def validateVPMEMFileSystem(region):
    '''
    Verify and create vPMEM file systems under /dev/pmem based on the specified
    region by using the blkid and mkfs.xfs commands. The script exits immediatly
    with an exit code in case the mkfs.xfs command fails.
    @param: region (str): Region for which a vPMEM volume will be created under
            /dev/pmem.
    @return: True (bool) in case the mkfs.xfs succeeds and False if the given
             region string has not the expected format.
    '''
    trace(TL.INFO, "Validating vPMEM file system for region: %s.", region)

    rno = ''
    match = re.search(r'region(\d+)', region)
    if match:
        rno = match.group(1)
    else:
        trace(TL.ERROR, "Invalid region string '%s' when creating file system.",
              region)
        return False

    cmd = [BLKID_TOOL_PATH, '/dev/pmem' + rno]
    _, _, ret = runCmd(cmd)
    if ret != 0 or vpmemRebuildFS:
        trace(TL.DEBUG, "Create filesystem on /dev/pmem%s", rno)
        cmd = [MKFS_TOOL_PATH, '-q', '-f', '-b', 'size=64K', '-s', 'size=512', '/dev/pmem' + rno]
        if vpmemDistro.lower().startswith("red"):
            cmd.insert(7,'reflink=0')
            cmd.insert(7, '-m')
        runCmdExitOnError(cmd)
    else:
        trace(TL.DEBUG, "Valid filesystem found on /dev/pmem%s", rno)

    return True

def unmountVPMEMFileSystem(region):
    '''
    Unmount the vPMEM file systems under /dev/pmem based on the specified
    region by using the Linux umount command.
    @param: region (str): Region for which the vPMEM volume will be unmounted
            under /dev/pmem.
    @return: False (bool) if the given region string has the wrong format
             otherwise True.
    '''
    trace(TL.INFO, "Unmounting vPMEM file system for region: %s.", region)

    rno = ''
    match = re.search(r'region(\d+)', region)
    if match:
        rno = match.group(1)
        path = '/dev/pmem' + rno
        unmountCmd(path, printErr=False)
    else:
        trace(TL.ERROR, "Invalid region string '%s' when unmounting file "
              "system.", region)
        return False

    return True

def mountVPMEMFileSystem(region, basemnt, sid):
    '''
    Mount the vPMEM file systems under a mountpoint for the specified region and
    HANA instance number by using the following commands:
        - ndbus
        - mountpoint
        - mkdir
        - mount
        - chown
        - chmod
    The function will use the following global variable used for further
    processing:
        - vpmemMntIndex: Index (int) used to enumerate the vPMEM volumes in case
                         the vpmemFSSimpleNumbering flag has been selected.
    @param: region (str): Region for which the vPMEM volumes will be mounted
            under the specfied (base) mountpoint.
    @param: basemnt (str): Base mount point used for all vPMEM volumes to be
            mounted.
    @param: sid (str): HANA instance ID used for mounting the vPMEM volumes.
    @return: tuple of (numaNode, mntPoint) (str, str): Valid NUMA node and mount
             point for the specified region if all commands succeed otherwise
             empty strings.
    '''
    global vpmemMntIndex
    trace(TL.INFO, "Mounting vPMEM file system for region: %s.", region)

    numaNode = ''
    mntPoint = ''
    basemnt = basemnt + '/' + sid.upper()
    rno = ''
    match = re.search(r'region(\d+)', region)
    if match:
        rno = match.group(1)
    else:
        trace(TL.ERROR, "Invalid region string '%s' when mounting file "
              "system.", region)
        return (numaNode, mntPoint)

    user = sid.lower() + "adm"

    path = '/sys/devices/ndbus' + rno + '/region' + rno+ '/numa_node'
    cmd = [CAT_TOOL_PATH, path]
    sout, serr, ret = runCmd(cmd)
    if ret != 0:
        trace(TL.ERROR, "Error: cmd: %s rc: %d serr: %s", cmd, ret, serr)
        return (numaNode, mntPoint)

    numaNode = sout.strip()
    if vpmemFSSimpleNumbering:
        mntPoint = basemnt + '/vol' + str(vpmemMntIndex)
        vpmemMntIndex += 1
    else:
        mntPoint = basemnt + '/node' + numaNode

    cmd = [MOUNTPOINT_TOOL_PATH, '-q', mntPoint]
    _, _, ret = runCmd(cmd)
    if ret == 0:
        if numaNode not in vpmemNUMANodeIdDict:
            vpmemNUMANodeIdDict[numaNode] = 1
        while True:
            # Create dot-notation
            if vpmemFSSimpleNumbering:
                mntPoint = basemnt + '/vol' + str(vpmemMntIndex) + '.' + \
                            str(vpmemNUMANodeIdDict[numaNode])
            else:
                mntPoint = basemnt + '/node' + numaNode + '.' + \
                            str(vpmemNUMANodeIdDict[numaNode])
            cmd = [MOUNTPOINT_TOOL_PATH, '-q', mntPoint]
            _, _, ret = runCmd(cmd)
            if ret == 0:
                vpmemNUMANodeIdDict[numaNode] += 1
            else:
                break

    trace(TL.DEBUG, "Mount /dev/pmem%s on %s", rno, mntPoint)

    cmd = [MKDIR_TOOL_PATH, '-p', mntPoint]
    runCmdExitOnError(cmd)
    cmd = [MOUNT_TOOL_PATH, '-o', 'dax', '/dev/pmem' + rno, mntPoint]
    runCmdExitOnError(cmd)
    cmd = [CHOWN_TOOL_PATH, user, mntPoint]
    runCmdExitOnError(cmd)
    cmd = [CHMOD_TOOL_PATH, '700', mntPoint]
    runCmdExitOnError(cmd)

    trace(TL.DEBUG, "Mounted file system: %s", mntPoint)
    trace(TL.DEBUG, "NUMA node ID: %s", numaNode)

    return (numaNode, mntPoint)

def createHANACfgFile(cfgFilePath, createIfNotExist=True):
    '''
    Create HANA configuration files if createIfNotExist is True (default).
    @param: cfgFilePath (str): Path of the configuartion file to create.
    @param: createIfNotExist (bool): If True, create the file if it does not
            exist otherwise print just a warning message.
    @return: (bool): False, if creating the configuration file fails otherwise
             True.
    '''
    if not os.path.exists(cfgFilePath):
        if createIfNotExist:
            trace(TL.INFO, "Creating HANA configuraion file %s", cfgFilePath)
            try:
                fh = open(cfgFilePath, 'w', encoding="utf-8")
            except OSError as e:
                trace(TL.ERROR, "HANA host configuration file %s cannot be "
                      "created: %s", cfgFilePath, str(e))
                return False
            fh.close()
            dirname = os.path.dirname(cfgFilePath)
            cmd = [CHOWN_TOOL_PATH, '--reference=' + dirname, cfgFilePath]
            runCmd(cmd)
        else:
            trace(TL.WARNING, "HANA host configuration file %s does not exist",
                  cfgFilePath)
    return True

def deleteDataOnNodeChange(fileSystemList, curNUMANodeList, prevNUMANodeList,
                           fileSystemType):
    '''
    Removing filesystems if the current NUMA node list and the previous NUMA
    node list (read from the topology file) differs by unmounting the file
    systems first and then removing them by using the Linux rm command.
    @param: fileSystemList (list): List of file systems to be removed.
    @param: curNUMANodeList (list): Current NUMA node list extracted when this
            script has been started.
    @param: prevNUMANodeList (list): Previous NUMA node list read from the
            topology file (option -t) sometime in the past when the script has
            been executed with the -g option (aka recording NUMA topology).
    @param: fileSystemType (str): Specifies the file system type (tmpfs or vPMEM).
    @return: True (bool) if all commands succeed. In case the rm fails the
             script exists immediatly.
    '''
    fsType = fileSystemType if fileSystemType == "tmpfs" else "vPMEM"
    trace(TL.INFO, "Check NUMA node locations for %s filesystems:", fsType)
    for fs in fileSystemList:
        trace(TL.INFO, "      %s", fs)

    if naturalSort(prevNUMANodeList) != naturalSort(curNUMANodeList):
        trace(TL.DEBUG, "Previous NUMA node list: %s", prevNUMANodeList)
        trace(TL.DEBUG, "Current NUMA node list: %s", curNUMANodeList)
        trace(TL.INFO, "Socket topology change detected. Removing "
              "filesystems: %s", fileSystemList)
        for fs in fileSystemList:
            # Unmount first, otherwise the 'rm -r fs' will fail with E_DEV_BUSY
            unmountCmd(fs, True)
            cmd = [RM_TOOL_PATH, '-r', fs]
            runCmdExitOnError(cmd)
    else:
        trace(TL.INFO, "No socket topology change detected.")

    return True

def updateHANACfg(sid, instNo, instHost, fileSystemList):
    '''
    Update following HANA configuration files:
        - global.ini
        - indexserver.ini
    located in /usr/sap/<SID>/HDB<INSTANCE>/<hostname>/.
    In the global.ini the basepath_persistent_memory_volumes parameter in the
    persistence section will be updated with the created file systems for vPMEM
    or tmpfs.
    In the indexserver.ini the table_default parameter (boolean value) in the
    persistent_memory section will be updated in case the vpmemActivateUsage
    flag (option '-a') has been specified.
    @param: sid (str): HANA SID used for the basepath of the configuration files.
    @param: instNo (str): HANA instance number used for the basepath of the
            configuration files.
    @param: instHost (str): Short hostname used for the basepath of the
            configuration files.
    @param: fileSystemList (list): List of file systems which will be written to
            the global.ini.
    @return: False (bool) if:
             - creating configuration files fails for some reason.
             - the global.ini configuration file does not contain the necessary
               parameter.
             otherwise True.
    '''
    trace(TL.INFO, "Updating HANA config files.")

    baseFilePath = "/usr/sap/" + sid + "/HDB" + instNo + "/" + instHost
    hostGlobalIniFilePath = baseFilePath + "/global.ini"
    if not createHANACfgFile(hostGlobalIniFilePath):
        return False

    hostIndexserverIniFilePath = baseFilePath + "/indexserver.ini"
    if not createHANACfgFile(hostIndexserverIniFilePath, vpmemActivateUsage):
        return False

    section = 'persistence'
    parameter = 'basepath_persistent_memory_volumes'
    config = configparser.ConfigParser()
    config.read(hostGlobalIniFilePath)
    if not config.has_section(section):
        trace(TL.DEBUG, "%s does not contain a section called '%s'; adding it.",
              hostGlobalIniFilePath, section)
        config.add_section(section)
    if not config.has_option(section, parameter) and not vpmemActivateUsage:
        trace(TL.DEBUG, "%s does not contain a %s parameter; adding it.",
              hostGlobalIniFilePath, parameter)
    config[section][parameter] = ';'.join(fileSystemList)
    with open(hostGlobalIniFilePath, 'w', encoding="utf-8") as configfile:
        config.write(configfile, False)
    trace(TL.INFO, "HANA host configuration file %s updated parameter: %s",
          hostGlobalIniFilePath, parameter)

    if vpmemActivateUsage:
        config.clear()
        config.read(hostIndexserverIniFilePath)
        section = 'persistent_memory'
        parameter = 'table_default'
        if not config.has_section(section):
            trace(TL.DEBUG, "%s does not contain a section called '%s'; "
                  "adding it.", hostIndexserverIniFilePath, section)
            config.add_section(section)
        if not config.has_option(section, parameter):
            config[section][parameter] = 'on'
        with open(hostIndexserverIniFilePath, 'w', encoding="utf-8") as configfile:
            config.write(configfile, False)
        trace(TL.INFO, "HANA host configuration file %s updated parameter: %s",
              hostIndexserverIniFilePath, parameter)

    return True

def verifyAndSetupMountPoints(cfgFilePath, curNUMANodeIds, prevNUMANodeIds,
                              tmpfsTotalMemSize):
    '''
    Read the script configuration file (JSON based: vpmem_hana.cfg) and depending
    on the file system type (vPMEM or tmpfs based) is does:
        - for vPMEM:
            - gets regions by UUID
            - validates namespaces
            - unmounts vPMEM file systems
            - validates vPMEM file systems
            - mounts vPMEM file systems
        - for tmpfs:
            - gets existing tmpfs mount points based on SID
            - removes all tmpfs mount points
            - creates all tmpfs mount points
    @param: cfgFilePath (str): Path to the (JSON based) configuration file this
            script is using (via the -c option)
    @param: curNUMANodeIds (list): List of current NUMA node IDs (integer
            strings) extracted when this script started.
    @param: prevNUMANodeIds (list): List of previous NUMA node IDs (integer
            strings) read from a specified topology file (specified by the
            '-t' option).
    @param: tmpfsTotalMemSize (str): Total memory size of tmpfs filesystems
            specified by the caller of this script.
    @return: (bool): False in case of an error otherwise True.
    '''
    myFileSystemList = []
    myNUMANodesList = []

    # Does the startup configuration file exists?
    if not os.path.exists(cfgFilePath):
        trace(TL.ERROR, "%s does not exist.", cfgFilePath)
        return False

    # Verify if the configuration file has a valid JSON structure
    if not verifyJSON(cfgFilePath):
        trace(TL.ERROR, "Verifying JSON structure of %s failed.", cfgFilePath)
        return False

    # Open and load JSON file into a list
    with open(cfgFilePath, encoding="utf-8") as scriptCfg:
        cfgData = json.load(scriptCfg)

    # Iterate over read sections of the JSON based configuration file
    for singleCfgEntry in cfgData:
        myFileSystemList.clear()
        myNUMANodesList.clear()

        # Sanity check of the configuration values. The check might modify the
        # passed configuration entries.
        (valid, singleCfgEntry) = verifyAndGetCfgInfo(singleCfgEntry,
                                                      cfgFilePath)
        if not valid:
            trace(TL.ERROR, "Verification of configuration in %s failed.",
                  cfgFilePath)
            return False

        if singleCfgEntry['type'] == "vpmem":
            # Only for vPMEM the PUUID parameter in the config file is set. In
            # this case it could be possible to have multiple UUIDs in this
            # parameter, hence the script has to iterate over those. Multiple
            # UUIDs are caused by multiple vPMEM volumes defined in the Power
            # HMC for the appropriate LPAR (for every single vPMEM volume one
            # UUID).
            for uuid in singleCfgEntry["puuid"]:
                regions = getRegionsByUuid(uuid)
                if len(regions) == 0:
                    return False
                for region in regions:
                    if not validateNamespace(region) or \
                       not unmountVPMEMFileSystem(region) or \
                       not validateVPMEMFileSystem(region):
                        return False
                    (numaNode, mountPath) = mountVPMEMFileSystem(region,
                                                                 singleCfgEntry['mnt'],
                                                                 singleCfgEntry['sid'])
                    if not mountPath or not numaNode:
                        return False
                    myNUMANodesList.append(numaNode)
                    myFileSystemList.append(mountPath)
                myNUMANodesList = naturalSort(myNUMANodesList)
                myFileSystemList = naturalSort(myFileSystemList)
        elif singleCfgEntry['type'] == "tmpfs":
            myNUMANodesList = curNUMANodeIds
            (valid, tmpfsMemSizePerNUMANode) = calcTmpFSMemSizes(tmpfsTotalMemSize,
                                                                 myNUMANodesList)
            if not valid:
                trace(TL.ERROR, "Invalid total memory size for tmpfs specified.")
                return False
            myFileSystemList = getTmpFSMnts(singleCfgEntry['mnt'],
                                            singleCfgEntry['sid'])
            listFileSystemSummary(singleCfgEntry['sid'], myFileSystemList,
                                  myNUMANodesList)
            if len(myFileSystemList) == 0 or vpmemRebuildFS:
                removeTmpfsAllMnts(myFileSystemList)
                myFileSystemList = createTmpFSMounts(singleCfgEntry['sid'],
                                                     singleCfgEntry['mnt'],
                                                     myNUMANodesList,
                                                     tmpfsMemSizePerNUMANode)
        deleteDataOnNodeChange(myFileSystemList, curNUMANodeIds,
                               prevNUMANodeIds, singleCfgEntry['type'])
        if not updateHANACfg(singleCfgEntry['sid'], singleCfgEntry['nr'],
                             singleCfgEntry['hostname'], myFileSystemList):
            return False
        listFileSystemSummary(singleCfgEntry['sid'], myFileSystemList,
                              myNUMANodesList)

    return True

# Main function ################################################################
def main():
    '''
    Main function. Containing the logic to:
        - get and parse the specified options.
        - set the global variables depending on the options.
        - initialize the script logger instance.
        - call the appropriate script functions depending on the options.
    '''
    # global variables set and used during this main function
    global vpmemScriptName
    global vpmemActivateUsage
    global vpmemRecordTopology
    global vpmemFSSimpleNumbering
    global vpmemRebuildFS
    global vpmemTopologyFile
    global vpmemDistro
    global vpmemLogFilePath
    global vpmemLogger
    tmpfsTotalMemSize = ''

    try:
        # Extract the script name
        vpmemScriptName = os.path.basename(sys.argv[0]).split('.')[0]

        # Setup the default log file path this script is using
        myhost = socket.gethostname().split('.')[0]
        vpmemLogFilePath = '/tmp/' + vpmemScriptName + '.' + myhost + '.log'

        listHelp = False
        listPUUID = False
        listVersion = False
        cfgFilePath = ''

        opts, _ = getopt.getopt(sys.argv[1:], 'ac:ghl:s:nprt:v')
        for name, value in opts:
            if name == '-a':
                vpmemActivateUsage = True
            elif name == '-c':
                cfgFilePath = value
            elif name == '-g':
                vpmemRecordTopology = True
            elif name ==  '-h':
                listHelp = True
            elif name == '-l':
                # Log file path specified by caller
                vpmemLogFilePath = value
            elif name == '-s':
                tmpfsTotalMemSize = value
            elif name == '-n':
                vpmemFSSimpleNumbering = True
            elif name == '-p':
                listPUUID = True
            elif name == '-r':
                vpmemRebuildFS = True
            elif name == '-t':
                vpmemTopologyFile = value
            elif name == '-v':
                listVersion = True
    except getopt.GetoptError as e:
        epilogAndExit("%s\n" % e, 1, True)
    except Exception as e:
        epilogAndExit("Exception occurred:\n%s\n" % e, 1, True)

    # Create the logger instance the script is using
    vpmemLogger = initLogger(vpmemLogFilePath)

    # Print a nice header to the log file
    trace(TL.DEBUG, "=== Starting %s ========================================",
          vpmemScriptName)
    trace(TL.DEBUG, "Script (version: %s) called: %s",
          VPMEM_SCRIPT_VERSION, sys.argv)

    if listHelp:        # '-h' option
        epilogAndExit("Help\n" + (USAGE % sys.argv[0]), 0)
    elif listPUUID:     # '-p' option
        listPUUIDs()
        epilogAndExit("", 0)
    elif listVersion:   # '-v' option
        epilogAndExit("%s: version %s" % (vpmemScriptName,
                                          VPMEM_SCRIPT_VERSION), 0)

    # Some sanity checks.
    if not vpmemRecordTopology and len(cfgFilePath) == 0:
        epilogAndExit("Option '-c', '-g' or '-p' required\n", 1, True)
    elif vpmemRecordTopology and len(vpmemTopologyFile) == 0:
        epilogAndExit("A topology file must be specified (option '-t')\n", 1, True)

    # Extract the distro this script is running on.
    (_, vpmemDistro) = getValueFromFileWithKeyAndDelimiter(
                        "/etc/os-release", '=', "PRETTY_NAME")
    trace(TL.DEBUG, "Distro this script is running on: '%s'", vpmemDistro)

    # First, extract the NUMA nodes.
    (curNUMANodeIds, prevNUMANodeIds) = getNUMANodes(vpmemRecordTopology,
                                                     vpmemTopologyFile)
    # If just storing the topology the script ends here.
    if vpmemRecordTopology:
        epilogAndExit("Recording topology succeeded.", 0)

    # Second, verify the permission this script runs on and the expected
    # dependencies.
    if not verifyPermissions():
        epilogAndExit("Verifying script permissions failed.", 1)
    if not verifyDependencies():
        epilogAndExit("Verifying expected dependencies for script failed.", 1)

    if tmpfsTotalMemSize:
        if not tmpfsTotalMemSize.strip().upper().endswith(('KB', 'MB', 'GB', 'TB')):
            epilogAndExit("Option '-s' expects single string, e.g. 1024KB or "
                          "512MB or 128GB or 1TB.\n", 1)

    # Third, call the major function to verify and setup the mount points for
    # either vPMEM or tmpfs.
    if not verifyAndSetupMountPoints(cfgFilePath, curNUMANodeIds,
                                     prevNUMANodeIds, tmpfsTotalMemSize):
        epilogAndExit("Verifying and setup mount points failed.", 1)
    else:
        epilogAndExit("Verifying and setup mount points succeeded.", 0)

if __name__ == '__main__':
    main()

