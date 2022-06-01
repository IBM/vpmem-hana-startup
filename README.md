# vpmem-hana-startup

## Usage
```
Usage: vpmem_hana_startup.sh [-c <file>] [-a] [-l <file>] [-r] [-p] [-h]
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
```
## Examples
Typical usage to configure HANA ini files for vpmem usage:
```
lsh30163:~/vpmem # ./vpmem_hana_startup.sh -c vpmem.cfg -a
20220218.064815 [vpmem_hana_startup.sh:157693] = Start ==========================================
20220218.064816 [vpmem_hana_startup.sh:157693] Parameter: sid=JE2
20220218.064816 [vpmem_hana_startup.sh:157693] Parameter: instno=02
20220218.064816 [vpmem_hana_startup.sh:157693] Parameter: mnt=/hana/vpmem
20220218.064816 [vpmem_hana_startup.sh:157693] Parameter: puuid=119f6fd1-135d-4cc6-ba53-b3d8aedd0bd7
20220218.064816 [vpmem_hana_startup.sh:157693] Parameter: insthost=lsh30163
20220218.064816 [vpmem_hana_startup.sh:157693] PMEM regions found: region1 region3 region5 region6
20220218.064816 [vpmem_hana_startup.sh:157693] Unmount /dev/pmem1
20220218.064816 [vpmem_hana_startup.sh:157693] Valid filesystem found on /dev/pmem1
20220218.064816 [vpmem_hana_startup.sh:157693] Mount /dev/pmem1 on /hana/vpmem/JE2/node0
20220218.064816 [vpmem_hana_startup.sh:157693] Unmount /dev/pmem3
20220218.064816 [vpmem_hana_startup.sh:157693] Valid filesystem found on /dev/pmem3
20220218.064816 [vpmem_hana_startup.sh:157693] Mount /dev/pmem3 on /hana/vpmem/JE2/node1
20220218.064816 [vpmem_hana_startup.sh:157693] Unmount /dev/pmem5
20220218.064816 [vpmem_hana_startup.sh:157693] Valid filesystem found on /dev/pmem5
20220218.064816 [vpmem_hana_startup.sh:157693] Mount /dev/pmem5 on /hana/vpmem/JE2/node2
20220218.064816 [vpmem_hana_startup.sh:157693] Unmount /dev/pmem6
20220218.064816 [vpmem_hana_startup.sh:157693] Valid filesystem found on /dev/pmem6
20220218.064816 [vpmem_hana_startup.sh:157693] Mount /dev/pmem6 on /hana/vpmem/JE2/node3
20220218.064816 [vpmem_hana_startup.sh:157693] vPMEM filesystems: /hana/vpmem/JE2/node0;/hana/vpmem/JE2/node1;/hana/vpmem/JE2/node2;/hana/vpmem/JE2/node3
20220218.064816 [vpmem_hana_startup.sh:157693] HANA HOST configuration file /usr/sap/JE2/HDB02/lsh30163/global.ini updated: parameter basepath_persistent_memory_volumes
20220218.064816 [vpmem_hana_startup.sh:157693] HANA HOST configuration file /usr/sap/JE2/HDB02/lsh30163/indexserver.ini updated: parameter table_default
```
The -p option can be used to list discovered vpmem regions, their sizes, numa node locations and parent uuids.
```
# ./vpmem_hana_startup.sh -p
    vPMEM  Numa
   Region  Node          Size Parent UUID
---------- ---- ------------- ------------------------------------
   region0    1     536870912 14fc9d96-02ca-468f-8075-6d9b6fa6f807
   region1    0    7516192768 119f6fd1-135d-4cc6-ba53-b3d8aedd0bd7
   region2    2    1879048192 14fc9d96-02ca-468f-8075-6d9b6fa6f807
   region3    1    7516192768 119f6fd1-135d-4cc6-ba53-b3d8aedd0bd7
   region4    3    1879048192 14fc9d96-02ca-468f-8075-6d9b6fa6f807
   region5    2   46170898432 119f6fd1-135d-4cc6-ba53-b3d8aedd0bd7
   region6    3   46170898432 119f6fd1-135d-4cc6-ba53-b3d8aedd0bd7
```

## User Configuration Flow:
- On the HMC, create a vPMEM volume for the HANA partition. Mark the vPMEM volume as optimized for affinity.
- In the partition, use script -p option, to get the parent UUIDs of created volumes.
- Create/update a hana_vpmem.cfg config file with the path to the HANA configuration file, the UUID of the vPMEM volume, and the location where the vPMEM volumes should get mounted. 
- Create/update a hana_vpmem.service systemd unit file to execute the startup script on boot

## Implementation:
- Scans a supplied configuration file to determine:
   - the parent UUID of the vPMEM volumes
   - the HANA sid
   - the parent directory under which to mount the vpmem filesystems
- Searches the device tree to locate the vPMEM devices associated with the UUID.
   - For devices optimized for affinity (the expected case), multiple child volumes may be discovered.
- Checkes if the devices have a valid file system on them.
   - If no valid file systems found, format them with an xfs filesystem.
- Mounts each of the filesystems to a mount point representing their SID and NUMA associativity.
- Updates the HANA configuration file to reflect where the vPMEM devices are mounted for each NUMA domain.

## Assumptions:
- vPMEM usage is already activated in the HANA ini scripts or the -a option should be used
- Default to xfs filesystems -b 64k -s 512

## Dependencies:
- jq
- ndctl

## Installation:
 1. Choose a location for the script and config file (referred to as /mountpoint/path/to below)
 2. Create /mountpoint/path/to/vpmem_hana.cfg
```
    [
      {
        "sid"       : "<HANA instance name. Required.>"
        ,"nr"       : "<HANA instance number. Required.>"
        ,"hostname" : "<HANA host. If not specified, the environment variable HOSTNAME will be used.>"
        ,"puuid    ": "<parent vpmem volume uuid. Required.>"
        ,"mnt"      : "<filesystem path to mount vpmem filesystems under. Required.>"
      }
    ]
```
 3. Create /etc/systemd/system/vpmem_hana.service taking care of NOTEs below
```
    [Unit]
    Description=Virtual PMEM SAP HANA Startup Script
    # NOTE: Ensure path to script is mounted. Replace /mountpoint as appropriate
    RequiresMountsFor=/mountpoint

    [Service]
    Type=oneshot
    # NOTE: Adjust the path to the startup script. Replace /mountpoint/path/to as appropriate
    ExecStart=/bin/sh -c "/mountpoint/path/to/vpmem_hana_startup.sh -c /mountpoint/path/to/vpmem_hana.cfg -a"

    [Install]
    WantedBy=multi-user.target
```
 4. Start service now and on reboot
```
    systemctl start vpmem_hana.service
    systemctl status vpmem_hana.service
    systemctl enable vpmem_hana.service
```

