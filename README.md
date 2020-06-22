# vpmem-hana-startup

## Usage
```
vpmem_hana_startup.sh [-c <file>] [-l <file>] [-p] [-h]
 OPTIONS
 ============  =========================================
 -c <file>     Full path configuration file
 -l <file>     Full path log file
 -p            List volume parent UUIDs
 -h            Help
```

## User Configuration Flow:
- On the HMC, create a vPMEM volume for the HANA partition. Mark the vPMEM volume as optimized for affinity.
- In the partition, use script -p option, to get the parent UUIDs of created volumes.
- Create/update a hana_vpmem.cfg config file with the path to the HANA configuration file, the UUID of the vPMEM volume, and the location where the vPMEM volumes should get mounted.
- Create/update a hana_vpmem.service systemd unit file to execute the startup script on boot

## Implementation
- Scans a supplied configuration file to determine:
   - the parent UUID of the vPMEM volumes
   - the HANA sid
   - the parent directory under which to mount the vpmem filesystems
- Searches the device tree to locate the vPMEM devices associated with the UUID.
   - For devices optimized for affinity (the expected case), multiple child volumes may be discovered.
- Checkes if the devices have a valid file system on them.
   - If no valid file systems found, format them with an xfs filesystem.
- Mounts each of the filesystems to a mount point representing their NUMA associativity.
- Updates the HANA configuration file to reflect where the vPMEM devices are mounted for each NUMA domain.

## Assumptions:
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
        "sid"   : "<HANA instance name>"
        ,"puuid": "<parent vpmem volume uuid>"
        ,"mnt"  : "<filesystem path to mount vpmem filesystems under>"
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
    ExecStart=/bin/sh -c "/mountpoint/path/to/vpmem_hana_startup.sh -c /mountpoint/path/to/vpmem_hana.cfg"

    [Install]
    WantedBy=multi-user.target
```
 4. Start service now and on reboot
```
    systemctl start vpmem_hana.service
    systemctl status vpmem_hana.service
    systemctl enable vpmem_hana.service
```

