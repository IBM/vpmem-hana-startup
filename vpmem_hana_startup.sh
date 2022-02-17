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
# - vPMEM usage is already activated in the HANA ini scripts
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
#        ,"nr"   : "<HANA instance number>"
#        ,"host" : "<HANA host>"
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
Usage: $NAME [-c <file>] [-l <file>] [-r] [-p] [-h] 
 OPTIONS
 ============  =========================================
 -c <file>     Full path configuration file
 -l <file>     Full path log file
 -r            Recreate filesystem. This option forces recreation of the filesystem(s) regardless of whether valid or not.
 -n            Filesystem numbering by index. Default is by numa node.
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
    local -r ex_reg=$(lsprop /sys/devices/ndbus*/region*/of_node/ibm,unit-parent-guid | grep -o 'region[0-9]\+')
    readarray -t regions <<<"$ex_reg"
    printf "%10s %4s %13s %s\n" "vPMEM " "Numa" "" ""
    printf "%10s %4s %13s %s\n" "Region " "Node" "Size" "Parent UUID"
    printf "%10s %4s %13s %s\n" "----------" "----" "-------------" "------------------------------------"
    for reg in "${regions[@]}"
    do
        local puuid=$(tr -d '\0' < /sys/devices/ndbus*/${reg}/of_node/ibm,unit-parent-guid)
        local size=$(tr -d '\0' < /sys/devices/ndbus*/${reg}/size)
        local numanode=$(tr -d '\0' < /sys/devices/ndbus*/${reg}/numa_node)
        printf "%10s %4d %13d %s\n" $reg $numanode $size $puuid
    done
}

function get_regions_by_uuid() {
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
    if [[ $? -ne 0 || $REBUILD_FS == true ]]; then
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
    local mntpoint

    if [[ $FS_SIMPLE_NUMBERING == true ]]; then
        mntpoint=${basemnt}/vol${mntindex}
        ((mntindex++))
    else
        local -r numa_node=$(cat /sys/devices/ndbus$rno/region$rno/numa_node)
        mntpoint=${basemnt}/node${numa_node}
        /usr/bin/mountpoint -q $mntpoint
        if [[ $? == 0 ]]; then
            if [[ -z ${nid_list[$numa_node]} ]]; then
                declare -i nid_list[$numa_node]=1
            fi
            while true;
            do
                mntpoint=${basemnt}/node${numa_node}.${nid_list[$numa_node]}
                /usr/bin/mountpoint -q $mntpoint
                if [[ $? == 0 ]]; then
                    nid_list[$numa_node]+=1
                else
                    break
                fi
            done
        fi
    fi

    log "Mount /dev/pmem$rno on $mntpoint"
    runCommandExitOnError /usr/bin/mkdir -p $mntpoint
    runCommandExitOnError /usr/bin/mount -o dax /dev/pmem$rno $mntpoint
    runCommandExitOnError /usr/bin/chown $user $mntpoint
    runCommandExitOnError /usr/bin/chmod 700 $mntpoint
    [[ ! -z "$vpmem_fs_list" ]] && vpmem_fs_list+=";"
    vpmem_fs_list+=$mntpoint
}

function update_hana_cfg() {
    log "vPMEM filesystems: $vpmem_fs_list"
    local -r sid=${1^^}
    local -r instno=$2
    local -r insthost=$3
    local -r config_file="/usr/sap/$sid/HDB${instno}/${insthost}/global.ini"
    local -r param="basepath_persistent_memory_volumes"
    if [[ ! -f $config_file ]]; then
        logError "HANA Host configuration file $config_file does not exist"
        exit 1;
    fi
    grep $param $config_file > /dev/null 2>&1 
    local -r rc=$?
    if [[ $rc != 0 ]]; then
        logError "$config_file does not contain a 'basepath_persistent_memory_volumes' property."
        exit 1;
    else
        runCommandExitOnError 'sed -i "s#^${param}.*\$#${param}=${vpmem_fs_list}#g" $config_file'
        log "HANA HOST configuration file $config_file updated"
    fi
}

# Main #################################################
NAME=$(basename $0)
VERSION="1.5"
DISTRO=$(grep PRETTY_NAME /etc/os-release | sed 's/PRETTY_NAME=//g' | tr -d '="')

# Defaults
declare LOGFILE="/tmp/${NAME}.log"
declare CONFIG_VPMEM=""
declare REBUILD_FS=false
declare FS_SIMPLE_NUMBERING=false
declare mntindex=0

declare -a regions
declare -a nid_list='()'
declare vpmem_fs_list=""

while getopts ":hc:l:prnv" opt; do
    case $opt in
        c) 
          CONFIG_VPMEM=$OPTARG
          ;;
        l) 
          LOGFILE=$OPTARG
          ;;
        r) 
          REBUILD_FS=true
          ;;
        n) 
          FS_SIMPLE_NUMBERING=true
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
    instno=$(echo $instance | jq .nr | tr -d '"' )
    insthost=$(echo $instance | jq .host | tr -d '"' )
    mnt=$(echo $instance | jq .mnt | tr -d '"')
    puuid=$(echo $instance | jq .puuid | tr -d '"')

    if [[ $insthost == null ]]
    then
        if [[ ! -z "$HOSTNAME" ]]
        then
            insthost=$HOSTNAME
        else
            logError "hostname not specified in script configuration file."
            exit 1;
        fi
    fi

    get_regions_by_uuid $puuid
    for element in "${regions[@]}"
    do
        validate_namespace $element
        unmount_vpmem_fs $element
        validate_vpmem_fs $element
        mount_vpmem_fs $element $mnt/$sid $sid 
    done
    update_hana_cfg $sid $instno $insthost
    unset regions
done

# EOF
