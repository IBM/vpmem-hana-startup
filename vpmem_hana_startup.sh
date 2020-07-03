#!/usr/bin/env bash
#
# IBM  "vpmem_hana_startup.sh": A convenience script to recreate vpmem filesystems on boot if required
#
# This script
#  - Scans a supplied configuration file to determine:
#    - the parent UUID of the vPMEM volumes
#    - the HANA sid
#    - the parent directory under which to mount the vpmem filesystems
#  - Searches the device tree to locate the vPMEM devices associated with the UUID.
#    - For devices optimized for affinity (the expected case), multiple child volumes may be discovered.
#  - Checkes if the devices have a valid file system on them.
#    - If no valid file systems found, format them with an xfs filesystem.
#  - Mounts each of the filesystems to a mount point representing their NUMA associativity.
#  - Updates the HANA configuration file to reflect where the vPMEM devices are mounted for each NUMA domain. 
#
# Assumptions:
# - Default to xfs filesystems -b 64k -s 512
#
# Dependencies:
# - jq
# - ndctl
#
# Installation:
# 1. Choose a location for the script and config file (referred to as /mountpoint/path/to below)
# 2. Create /mountpoint/path/to/vpmem_hana.cfg
#    [
#      {
#        "sid"   : "<HANA instance name>"
#        ,"puuid": "<parent vpmem volume uuid>"
#        ,"mnt"  : "<filesystem path to mount vpmem filesystems under>"
#      }
#    ]
# 3. Create /etc/systemd/system/vpmem_hana.service taking care of NOTEs below
#    [Unit]
#    Description=Virtual PMEM SAP HANA Startup Script
#    # NOTE: Ensure path to script is mounted. Replace /mountpoint as appropriate
#    RequiresMountsFor=/mountpoint
#
#    [Service]
#    Type=oneshot
#    # NOTE: Adjust the path to the startup script. Replace /mountpoint/path/to as appropriate
#    ExecStart=/bin/sh -c "/mountpoint/path/to/vpmem_hana_startup.sh -c /mountpoint/path/to/vpmem_hana.cfg"
#
#    [Install]
#    WantedBy=multi-user.target
# 4. Start service now and on reboot
#    systemctl start vpmem_hana.service
#    systemctl status vpmem_hana.service
#    systemctl enable vpmem_hana.service
#

# Utils ################################################
function usage() {
    cat <<EOUSAGE >&2
$@
Usage: $NAME [-c <file>] [-l <file>] [-p] [-h] 
 OPTIONS
 ============  =========================================
 -c <file>     Full path configuration file
 -l <file>     Full path log file
 -p            List volume parent UUIDs
 -v            Print version
 -h            Help
EOUSAGE
}

function log() {
    echo "$(date +%Y%m%d.%H%M%S) [$NAME:$$] $@"
}

function logError() {
    log "ERROR: $@"
}

verifyDependencies() {
    for cmd in "$@"
    do
        command -v $cmd >/dev/null 2>&1 || {
            logError "Required dependency $cmd not found"
            exit 1
        }
    done
}

verifyJSON() {
    if jq -e . >/dev/null 2>&1 <<<"$1"; then
        logError "$1 is not a valid JSON file"
        exit 2
    fi
}
verifyPermissions() {
    if [[ $EUID -ne 0 ]]; then
        logError "This script must be run as root"
        exit 3
    fi
}

function runCommandExitOnError() {
    local cmd="$*"
    eval $cmd
    local -r rc=$?
    if [[ $rc != 0 ]]; then
        logError "Error: rc=$rc, cmd='$cmd'\n"
        exit $rc
    fi
}

# Funcs ################################################
function list_puuids() {
    lsprop /sys/devices/ndbus*/region*/of_node/ibm,unit-parent-guid
}

function get_regions() {
    local -r uuid=$1
    local -r ex_reg=$(lsprop /sys/devices/ndbus*/region*/of_node/ibm,unit-parent-guid  | grep -B 1 $uuid | grep -o 'region[0-9]\+')
    readarray -t regions <<<"$ex_reg"
    log "PMEM regions found: ${regions[@]}"
}

function validate_namespace(){
    local -r region=$1
    local -r ns=$(ndctl list -N -r $region)
    if [[ -z $ns ]]; then
        log "Create namespace for region $region"
        local -ri rno=${region#"region"}
        runCommandExitOnError ndctl disable-region region$rno
        runCommandExitOnError ndctl zero-labels nmem$rno
        runCommandExitOnError ndctl init-labels nmem$rno
        runCommandExitOnError ndctl enable-region region$rno
        runCommandExitOnError ndctl create-namespace -m fsdax -r region$rno
    fi
}

function validate_vpmem_fs() {
    local -r region=$1
    local -ri rno=${region#"region"}
    blkid /dev/pmem$rno > /dev/null
    if [[ $? -ne 0 ]]; then
        log "Create filesystem on /dev/pmem$rno"
        local -r REFLINK=""
        if [[ ${DISTRO,,} == "red"* ]]; then
            REFLINK="-m reflink=0"
        fi
        runCommandExitOnError mkfs.xfs -f -b size=64K -s size=512 $REFLINK /dev/pmem$rno
    else
        log "Valid filesystem found on /dev/pmem$rno"
    fi
}

function unmount_vpmem_fs() {
    local -r region=$1
    local -ri rno=${region#"region"}
    log "Unmount /dev/pmem$rno"
    while umount -f /dev/pmem$rno 2>/dev/null; do :; done
    return 0
}

function mount_vpmem_fs() {
    local -r region=$1
    local -ri rno=${region#"region"}
    local -r basemnt=$2
    local -r user=${3,,}adm
    local -r numa_node=$(cat /sys/devices/ndbus$rno/region$rno/numa_node)

    local -r mnt_numa=${basemnt}/node${numa_node}
    /usr/bin/mountpoint -q $mnt_numa
    if [[ $? == 0 ]]; then
        if [[ -z ${nid_list[$numa_node]} ]]; then
            declare -i nid_list[$numa_node]=1
        fi
        while true;
        do
            mnt_numa=${basemnt}/node${numa_node}.${nid_list[$numa_node]}
            /usr/bin/mountpoint -q $mnt_numa
            if [[ $? == 0 ]]; then
                nid_list[$numa_node]+=1
            else
                break
            fi
        done
    fi

    log "Mount /dev/pmem$rno on $mnt_numa"
    runCommandExitOnError /usr/bin/mkdir -p $mnt_numa
    runCommandExitOnError /usr/bin/mount -o dax /dev/pmem$rno $mnt_numa
    runCommandExitOnError /usr/bin/chown $user $mnt_numa
    runCommandExitOnError /usr/bin/chmod 700 $mnt_numa
    [[ ! -z "$vpmem_fs_list" ]] && vpmem_fs_list+=";"
    vpmem_fs_list+=$mnt_numa
}

function update_hana_cfg() {
    log "vPMEM filesystems: $vpmem_fs_list"
    local -r sid=${1^^}
    local -r config_file="/usr/sap/$sid/SYS/global/hdb/custom/config/global.ini"
    local -r param="basepath_persistent_memory_volumes"
    runCommandExitOnError 'sed -i "s#^${param}.*\$#${param}=${vpmem_fs_list}#g" $config_file'
    log "HANA configuration file $config_file updated"
}

# Main #################################################
NAME=$(basename $0)
VERSION="1.1"
DISTRO=$(grep PRETTY_NAME /etc/os-release | sed 's/PRETTY_NAME=//g' | tr -d '="')

# Defaults
declare LOGFILE="/tmp/${NAME}.log"
declare CONFIG_VPMEM=""

declare -a regions
declare -a nid_list='()'
declare vpmem_fs_list=""

while getopts ":hc:l:pv" opt; do
    case $opt in
        c) 
          CONFIG_VPMEM=$OPTARG
          ;;
        l) 
          LOGFILE=$OPTARG
          ;;
        p) list_puuids ; exit 0;;
        v) echo "$NAME: version $VERSION" ; exit 0;;
        h) usage "Help" ; exit 0;;
        :) usage "Option -${OPTARG} requires an argument." ; exit 1 ;;
        \?) usage "Invalid option -${OPTARG}" ; exit 1;;
    esac
done
shift $((OPTIND-1))

exec &> >(tee -a "$LOGFILE")
exec 2>&1

log "= Start =========================================="
verifyPermissions 
verifyDependencies "ndctl" "jq"
verifyJSON $CONFIG_VPMEM

jq -rc '.[]' $CONFIG_VPMEM | while IFS='' read instance
do
    sid=$(echo $instance | jq .sid | tr -d '"' )
    mnt=$(echo $instance | jq .mnt | tr -d '"')
    puuid=$(echo $instance | jq .puuid | tr -d '"')

    get_regions $puuid
    for element in "${regions[@]}"
    do
        validate_namespace $element
        unmount_vpmem_fs $element
        validate_vpmem_fs $element
        mount_vpmem_fs $element $mnt $sid 
    done
    update_hana_cfg $sid
    unset regions
done

# EOF
