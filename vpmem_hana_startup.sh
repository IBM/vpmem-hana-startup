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
#        "sid"       : "<HANA instance name>"
#        ,"nr"       : "<HANA instance number>"
#        ,"hostname" : "<HANA host>"
#        ,"puuid"    : "<parent vpmem volume uuid>"
#        ,"mnt"      : "<filesystem path to mount vpmem filesystems under>"
#      }
#      {
#        "sid"       : "<HANA instance name>"
#        ,"nr"       : "<HANA instance number>"
#        ,"hostname" : "<HANA host>"
#        ,"mnt"      : "<filesystem path to mount tmpfs filesystems under>"
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
Usage: $NAME [-c <file>] [-a] [-l <file>] [-r] [-p] [-h] 
 OPTIONS
 ============  =========================================
 -c <file>     Full path configuration file
 -l <file>     Full path log file
 -r            Recreate filesystem. This option forces recreation of the filesystem(s) regardless of whether valid or not.
 -a            Activate vpmem usage in HANA ini files. Default updates only mount point locations.
 -n            Filesystem numbering by index. Default is by numa node.
 -p            List volume parent UUIDs
 -v            Print version
 -h            Help
EOUSAGE
}

function log() {
    echo "$(date +%Y%m%d-%H%M%S) [$NAME:$$] $@"
}

function logVerbose() {
#    if [[ $VERBOSE == true ]]; then
        log "$@"
#    fi
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
    cat $1 | jq -e . >/dev/null 2>&1 
    if [[ $? -ne 0 ]]; then
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
function get_cfg_info() {
    local -r instance=$1

    if echo $instance | jq -e 'has("sid")' > /dev/null; then
        sid=$(echo $instance | jq .sid | tr -d '"' )
        sidlc=${sid,,}
        siduc=${sid^^}
        log "Parameter: sid=$sid"
    else
        logError "SID not specified in script configuration file. Keyword: 'sid'"
        exit 1;
    fi

    if echo $instance | jq -e 'has("nr")' > /dev/null; then
        instno=$(echo $instance | jq .nr | tr -d '"' )
        log "Parameter: instno=$instno"
    else
        logError "Instance number not specified in script configuration file. Keyword: 'nr'"
        exit 1;
    fi

    if echo $instance | jq -e 'has("mnt")' > /dev/null; then
        mnt=$(echo $instance | jq .mnt | tr -d '"' )
        log "Parameter: mnt=$mnt"
    else
        logError "vPMEM volume filesystem mountpoint not specified in script configuration file.  Keyword: 'mnt'"
        exit 1;
    fi

    if echo $instance | jq -e 'has("puuid")' > /dev/null; then
        declare -ga puuid
        puuid=( $(echo $instance | jq '[.puuid] | flatten | values[]' | tr -d '"' ) )
        for uuid in "${puuid[@]}"
        do
            if [[ ${#uuid} -ne 36 ]]; then
                logError "Invalid UUID specified: $uuid"
                exit 1;
            fi
	    if [[ ! $uuid =~ ^\{?[A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12}\}?$ ]]; then
                logError "Invalid UUID specified: $uuid"
                exit 1;
            fi
	done
        log "Parameter: puuid=${puuid[@]}"
        pmem_type="vpmem"
    else
        pmem_type="tmpfs"
    fi

    if echo $instance | jq -e 'has("hostname")' > /dev/null; then
        insthost=$(echo $instance | jq .hostname | tr -d '"' )
    else
        if [[ ! -z "$HOSTNAME" ]]
        then
            insthost=$HOSTNAME
        else
            logError "Hostname not specified in script configuration file. Keyword: 'hostname'"
            exit 1;
        fi
    fi
    log "Parameter: host=$insthost"
    log "Parameter: type=$pmem_type"
}

function list_vpmem_summary() {
    local sid=$1
    IFS=';' read -r -a vpmem_nn_array <<< "$2"
    IFS=';' read -r -a vpmem_fs_array <<< "$3"

    printf "\nInstance: %3s\n" $sid
    printf "%4s %9s %9s %9s %13s %s\n" "Numa" "" "" "Percent " ""
    printf "%4s %9s %9s %9s %13s %s\n" "Node" "Available" "Used  " "Used  " "Mountpoint"
    printf "%4s %9s %9s %9s %13s %s\n" "----" "---------" "---------" "---------" "------------------------------------"
    if [[ ${#vpmem_nn_array[@]} -ne ${#vpmem_fs_array[@]} ]]; then
        logError "Error: numa node and file system list are of unequal length. Dubious results.";
    else
        for index in "${!vpmem_nn_array[@]}"
        do
            local nn=${vpmem_nn_array[$index]}
            local fs=${vpmem_fs_array[$index]}
            readarray -t -s1 dfout <<< $(df -h --output=avail,used,pcent $fs)
            local avail=${dfout[0]}
            local used=${dfout[1]}
            local pcent=${dfout[2]}
            printf "%4d %9s %9s %9s %s\n" $nn $avail $used $pcent $fs
        done
    fi
}

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

function get_tmpfs_mnts() {
    local sid=$1
    local mntparent=$2
    local node=-2

    log "Name         Mountpoint                                       Type     Options                          Node"
    log "------------ ------------------------------------------------ -------- -------------------------------- ----"
#    log mntparent=$mntparent
#    log "exec: grep $mntparent /proc/mounts | grep tmpfs | grep -i $sid "
    grep $mntparent /proc/mounts | grep tmpfs | grep -i $sid | while IFS=' ' read -r mntname mntpoint mnttype mntopts rest
    do
        node=-1
        if [[ $mntopts == *"prefer"* ]]; then
            node=${mntopts##*prefer:}
            node=${node%%,*}
        fi

        printf -v pad %32s
	local tmntname=$mntname$pad
	local tmntpoint=$mntpoint$pad
	local tmnttype=$mnttype$pad
	local tmntopts=$mntopts$pad
	local tnode=$node$pad

        log "${tmntname:0:12} ${tmntpoint:0:48} ${tmnttype:0:8} ${tmntopts:0:32} ${tnode:0:4}"

        [[ ! -z "$vpmem_fs_list" ]] && vpmem_fs_list+=";"
        vpmem_fs_list+=$mntpoint
        [[ ! -z "$vpmem_nn_list" ]] && vpmem_nn_list+=";"
        vpmem_nn_list+=$node
    done
}

function get_numa_nodes() {
#    log "LPAR Topology ->  Node Memory"
#    log "                  ---- ------"
    local nodepath
    local node
    for nodepath in /sys/devices/system/node/node*
    do
        node=${nodepath##*\/node}
#        printf -v tnode "%3d" $node
	if compgen -G "${nodepath}/memory*" > /dev/null; then
            numa_nodes+=($node)
#            log "                  $tnode    Y"
#        else
#            log "                  $tnode    N"
        fi
    done
    log "Numa nodes: ${numa_nodes[@]}"
}

function remove_tmpfs_all_mnts() {
    IFS=';' read -r -a vpmem_fs_array <<< "$1"
    local mnt
    for mnt in "${vpmem_fs_array[@]}"
    do
        while umount -f $mnt 2>/dev/null; do :; done
    done
}

function get_tmpfs_mounts_to_create() {
    local node
    for node in "${numa_nodes[@]}"
    do
        if [[ ! " ${tmpfs_nodes[@]} " =~ " ${node} " ]]; then
            tmpfs_create+=($node)
        fi
    done
}

function create_tmpfs_mounts() {

## TODO:
##   handle mnt name conflict
##
    local -r sidlc=${1,,}
    local -r siduc=${1^^}
    local -r mntparent=$2
    local node

    for node in "${numa_nodes[@]}"
    do

        local fs="$mntparent/$siduc/node$node"

        local cmd="mkdir -p $fs"
        logVerbose "Execute: $cmd"
        runCommandExitOnError $cmd

        cmd="mount tmpfs${siduc}${node} -t tmpfs -o mpol=prefer:${node} $fs"
        logVerbose "Execute: $cmd"
        runCommandExitOnError $cmd

        cmd="chown -R ${sidlc}adm:sapsys $fs"
        logVerbose "Execute: $cmd"
        runCommandExitOnError $cmd

        cmd="chmod 777 -R $fs"
        logVerbose "Execute: $cmd"
        runCommandExitOnError $cmd

        [[ ! -z "$vpmem_fs_list" ]] && vpmem_fs_list+=";"
        vpmem_fs_list+=$fs
        [[ ! -z "$vpmem_nn_list" ]] && vpmem_nn_list+=";"
        vpmem_nn_list+=$node

    done
}

function get_regions_by_uuid() {
    local -r uuid=$1
    local -r ex_reg=$(lsprop /sys/devices/ndbus*/region*/of_node/ibm,unit-parent-guid  | grep -B 1 $uuid | grep -o 'region[0-9]\+')

    if [[ -z "$ex_reg" ]]; then
        logError "No regions found for $uuid"
        exit 2
    fi
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
        runCommandExitOnError mkfs.xfs -q -f -b size=64K -s size=512 $REFLINK /dev/pmem$rno
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

    local -r numa_node=$(cat /sys/devices/ndbus$rno/region$rno/numa_node)
    if [[ $FS_SIMPLE_NUMBERING == true ]]; then
        mntpoint=${basemnt}/vol${mntindex}
        ((mntindex++))
    else
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
    [[ ! -z "$vpmem_nn_list" ]] && vpmem_nn_list+=";"
    vpmem_nn_list+=$numa_node
}

function create_hana_cfg() {
    local -r cfgfile=$1
    local -r exit_on_fail=$2
    if [[ ! -f $cfgfile ]]; then
        if [[ $ACTIVATE_USAGE == true ]]; then
            touch $cfgfile > /dev/null 2>&1                
            if [[ $? != 0 ]]; then
                logError "HANA Host configuration file $cfgfile cannot be created"
                exit 1;
            fi
            chown --reference=$(dirname $cfgfile) $cfgfile > /dev/null 2>&1                
        else
            if [[ $exit_on_fail == true ]]; then
                logError "HANA Host configuration file $cfgfile does not exist"
                exit 1;
            fi
        fi
    fi
}

function update_hana_cfg() {
    log "vPMEM filesystems: $vpmem_fs_list"
    local -r sid=${1^^}
    local -r instno=$2
    local -r insthost=$3

    local -r host_global_ini_file="/usr/sap/$sid/HDB${instno}/${insthost}/global.ini"
    create_hana_cfg $host_global_ini_file true

    local -r host_indexserver_ini_file="/usr/sap/$sid/HDB${instno}/${insthost}/indexserver.ini"
    create_hana_cfg $host_indexserver_ini_file false

    local -r basepath_param="basepath_persistent_memory_volumes"
    grep $basepath_param $host_global_ini_file > /dev/null 2>&1 
    if [[ $? != 0 ]]; then
        if [[ $ACTIVATE_USAGE == true ]]; then
            echo "[persistence]" >> $host_global_ini_file
            echo "basepath_persistent_memory_volumes=XXX" >> $host_global_ini_file
        else
            logError "$host_global_ini_file does not contain a 'basepath_persistent_memory_volumes' property."
            exit 1;
        fi
    fi
    runCommandExitOnError 'sed -i "s#^${basepath_param}.*\$#${basepath_param}=${vpmem_fs_list}#g" $host_global_ini_file'
    log "HANA HOST configuration file $host_global_ini_file updated: parameter $basepath_param"

    if [[ $ACTIVATE_USAGE == true ]]; then
        local -r table_param="table_default"
        grep $table_param $host_indexserver_ini_file > /dev/null 2>&1 
        if [[ $? != 0 ]]; then
            echo "[persistent_memory]" >> $host_indexserver_ini_file
            echo "table_default=XXX" >> $host_indexserver_ini_file
        fi
        runCommandExitOnError 'sed -i "s#^${table_param}.*\$#${table_param}=on#g" $host_indexserver_ini_file'
        log "HANA HOST configuration file $host_indexserver_ini_file updated: parameter $table_param"
    fi
}

# Main #################################################
NAME=$(basename $0)
VERSION="1.7"
DISTRO=$(grep PRETTY_NAME /etc/os-release | sed 's/PRETTY_NAME=//g' | tr -d '="')

shopt -s lastpipe

# Defaults
declare LOGFILE="/tmp/${NAME}.log"
declare CONFIG_VPMEM=""
declare ACTIVATE_USAGE=false
declare REBUILD_FS=false
declare FS_SIMPLE_NUMBERING=false
declare mntindex=0

declare -a regions
declare -a nid_list='()'
declare -a numa_nodes
declare vpmem_fs_list=""
declare vpmem_nn_list=""
declare pmem_type=""

while getopts ":hac:l:prnv" opt; do
    case $opt in
        c) 
          CONFIG_VPMEM=$OPTARG
          ;;
        l) 
          LOGFILE=$OPTARG
          ;;
        a) 
          ACTIVATE_USAGE=true
          ;;
        r) 
          REBUILD_FS=true
          ;;
        n) 
          FS_SIMPLE_NUMBERING=true
          ;;
        p) list_puuids; exit 0;;
        v) echo "$NAME: version $VERSION"; exit 0;;
        h) usage "Help"; exit 0;;
        :) usage "Option -${OPTARG} requires an argument."; exit 1;;
        \?) usage "Invalid option -${OPTARG}"; exit 1;;
    esac
done
shift $((OPTIND-1))

exec &> >(tee -a "$LOGFILE")
exec 2>&1

if [[ -z "$CONFIG_VPMEM" ]]; then
    usage "Option c or p required" ; exit 1;
fi

log "= Start =========================================="
log "version: $VERSION"
verifyPermissions 
verifyDependencies "ndctl" "jq"
verifyJSON $CONFIG_VPMEM

get_numa_nodes

jq -rc '.[]' $CONFIG_VPMEM | while IFS='' read instance
do
    get_cfg_info $instance

    if [[ $pmem_type == "vpmem" ]]; then
        for uuid in "${puuid[@]}"
        do            
            log "UUID $uuid"    
            get_regions_by_uuid $uuid
            for element in "${regions[@]}"
            do
                validate_namespace $element
                unmount_vpmem_fs $element
                validate_vpmem_fs $element
                mount_vpmem_fs $element $mnt/$siduc $sid 
            done
        done
    else
        get_tmpfs_mnts $sid $mnt/$siduc
        list_vpmem_summary $sid $vpmem_nn_list $vpmem_fs_list
        if [[ $REBUILD_FS == true ]]; then
            remove_tmpfs_all_mnts $vpmem_fs_list
            unset vpmem_fs_list
            unset vpmem_nn_list
            create_tmpfs_mounts $siduc $mnt
        fi
    fi
    update_hana_cfg $sid $instno $insthost
    list_vpmem_summary $sid $vpmem_nn_list $vpmem_fs_list
    unset pmem_type
    unset vpmem_fs_list
    unset vpmem_nn_list
    unset regions
done

# EOF
