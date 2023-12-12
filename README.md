# vpmem-hana-startup

## Usage
```
Usage: vpmem_hana_startup.py [-c <file>] [-t <file>] [-l <file>] [-s <size>] [-r] [-a] [-n] [-g] [-p] [-v] [-h]
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
 -h            Help.
```
## Examples
Typical usage to configure HANA ini files for vPMEM usage:
```
[root@myHost: ~]# ./vpmem_hana_startup.py -c ./vpmem.cfg -t ./topology.myHost
 Extracting NUMA nodes.
 Found 4 NUMA nodes.
 Verifying configuration parameters in ./vpmem.cfg.
 Valid UUID found: '6fa4cb92-1736-4543-8369-44a2d2a06fbe'.
 Config parameter (puuid): UUID=['6fa4cb92-1736-4543-8369-44a2d2a06fbe']
 Config parameter (sid): HANA SID=HDB
 Config parameter (nr): HANA instance no=00
 Config parameter (mnt): Mount point=/data/vpmem
 Config parameter (host): Host=myHost
 Config parameter (type): File system type=vpmem
 Getting regions for UUID: 6fa4cb92-1736-4543-8369-44a2d2a06fbe.
 4 regions found for UUID: 6fa4cb92-1736-4543-8369-44a2d2a06fbe
 Validating namespace for region: region0.
 Unmounting vPMEM file system for region: region0.
 Validating vPMEM file system for region: region0.
 Mounting vPMEM file system for region: region0.
 Validating namespace for region: region1.
 Unmounting vPMEM file system for region: region1.
 Validating vPMEM file system for region: region1.
 Mounting vPMEM file system for region: region1.
 Validating namespace for region: region2.
 Unmounting vPMEM file system for region: region2.
 Validating vPMEM file system for region: region2.
 Mounting vPMEM file system for region: region2.
 Validating namespace for region: region3.
 Unmounting vPMEM file system for region: region3.
 Validating vPMEM file system for region: region3.
 Mounting vPMEM file system for region: region3.
 Check NUMA node locations for vPMEM filesystems:
       /data/vpmem/HDB/node0
       /data/vpmem/HDB/node1
       /data/vpmem/HDB/node2
       /data/vpmem/HDB/node3
 No socket topology change detected.
 Updating HANA config files.
 HANA HOST configuration file /usr/sap/HDB/HDB00/myHost/global.ini updated parameter: basepath_persistent_memory_volumes
 File system summary:

Instance: HDB
Numa                       Percent
Node Available      Used      Used Mountpoint
---- --------- --------- --------- ------------------------------------
   0      499G     1016M        1% /data/vpmem/HDB/node0
   1      499G     1016M        1% /data/vpmem/HDB/node1
   2      499G     1016M        1% /data/vpmem/HDB/node2
   3      499G     1016M        1% /data/vpmem/HDB/node3

 Verifying and setup mount points succeeded.
[root@myHost: ~]#
```
The -p option can be used to list discovered vPMEM regions, their sizes, NUMA node locations and parent uuids.
```
[root@myHost: ~]# ./vpmem_hana_startup.py -p
    vPMEM  Numa
   Region  Node          Size Parent UUID
---------- ---- ------------- ------------------------------------
   region0    0  537139347456 6fa4cb92-1736-4543-8369-44a2d2a06fbe
   region1    1  537139347456 6fa4cb92-1736-4543-8369-44a2d2a06fbe
   region2    2  537139347456 6fa4cb92-1736-4543-8369-44a2d2a06fbe
   region3    3  537139347456 6fa4cb92-1736-4543-8369-44a2d2a06fbe
[root@myHost: ~]#
```
The -g option in conjunction with the -t option can be used to store the vPMEM topology to the specified file.
```
[root@myHost: ~]# ./vpmem_hana_startup.py -g -t ./topology.myHost
 Extracting NUMA nodes.
 Found 4 NUMA nodes.
 Writing 4 NUMA node IDs to ./topology.myHost.
 Recording topology succeeded.
[root@myHost: ~]#

[root@myHost: ~]# cat ./topology.myHost
0 1 2 3
[root@myHost: ~]#
```

## User Configuration Flow:
- On the HMC, create a vPMEM volume for the HANA partition. Mark the vPMEM volume as optimized for affinity.
- In the partition, use script -p option, to get the parent UUIDs of created volumes.
- In the partition, use script -g option, to store the vPMEM topology to a file.
- Create/update a hana_vpmem.cfg config file with the path to the HANA configuration file, the UUID of the vPMEM volume, and the location where the vPMEM volumes should get mounted.
- Create/update a hana_vpmem.service systemd unit file to execute the startup script on boot.

## Implementation:
- Scans a supplied configuration file to determine:
   - the parent UUID of the vPMEM volumes.
   - the HANA sid.
   - the parent directory under which to mount the vPMEM filesystems.
- Searches the device tree to locate the vPMEM devices associated with the UUID.
   - For devices optimized for affinity (the expected case), multiple child volumes may be discovered.
- Checkes if the devices have a valid file system on them.
   - If no valid file systems found, format them with an xfs filesystem.
- Mounts each of the filesystems to a mount point representing their SID and NUMA associativity.
- Updates the HANA configuration file to reflect where the vPMEM devices are mounted for each NUMA domain.

## Assumptions:
- vPMEM usage is already activated in the HANA ini scripts or the -a option should be used.
- Default to xfs filesystems -b 64k -s 512.

## Dependencies:
- /sbin/lsprop
- /usr/bin/ndctl
- /usr/bin/numactl

## Installation:
 1. Choose a location for the script and config file (referred to as /mountpoint/path/to below).
 2. Create /mountpoint/path/to/vpmem_hana.cfg.
```
    [
      {
        "sid"       : "<HANA instance name. Required.>"
        ,"nr"       : "<HANA instance number. Required.>"
        ,"hostname" : "<HANA host. If not specified, the environment variable HOSTNAME will be used.>"
        ,"puuid    ": "<Parent vPMEM volume uuid. Required.>"
        ,"mnt"      : "<Filesystem path to mount vPMEM filesystems under. Required.>"
      }
    ]
```
3. Create /etc/systemd/system/vpmem_hana_startup.service taking care of NOTEs below
```
    [Unit]
    Description=Virtual PMEM SAP HANA Startup Script
    # NOTE: Ensure path to script is mounted. Replace /mountpoint as appropriate
    RequiresMountsFor=/mountpoint

    [Service]
    Type=oneshot
    # NOTE: Adjust the path to the startup script. Replace /mountpoint/path/to as appropriate
    ExecStart=/bin/sh -c "/mountpoint/path/to/vpmem_hana_startup.py -c /mountpoint/path/to/vpmem_hana.cfg -a -t /mountpoint/path/to/vpmem_topology.sav"

    [Install]
    WantedBy=multi-user.target
```
4. Create /etc/systemd/system/vpmem_hana_shutdown.service taking care of NOTEs below
```
    [Unit]
    Description=Virtual PMEM SAP HANA Shutdown Script
    DefaultDependencies=no
    Before=shutdown.target

    [Service]
    Type=oneshot
    # NOTE: Adjust the path to the startup script. Replace /mountpoint/path/to as appropriate
    ExecStart=/bin/sh -c "/mountpoint/path/to/vpmem_hana_startup.py -g -t /mountpoint/path/to/vpmem_topology.sav"

    [Install]
    WantedBy=shutdown.target
```
 5. Start service now and on reboot
```
    systemctl start vpmem_hana.service
    systemctl status vpmem_hana.service
    systemctl enable vpmem_hana.service
```

