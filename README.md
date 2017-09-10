# partitionlist
Analyze bootrecord and list partition structure


This python script try to parse imagefiles or devices.
Parsing is possible, if you give the path to imagefile/device
as the -i option. Known formats are only raw images or if using
linux or mac os raw devices too. If you are using windows a analyze of
rawdevices isn't possible. Same applies to later explained partition
analyzes.

### Working method:
First the script check if a filesystem is present in the first sectors. It checks
for known filesystems to exclude that there's a VBR at this position. Than the script
read the first two sector and try to interpret the partitioning scheme with finding
the magic number '55 AA' for existing MBR. A second test checks if the 'EFI PART' Header
for GPT scheme can find in this area. The third test to determine the partitioning scheme
checks if there it's a hybrid boot sector.
Knowing the scheme, the script try to interpret the whole partition table. After finding
the partition position, the script try to verify the found partition with the signatures
in VBR. Additionally the script calculate the unallocated space between found partitions
The output should represent a complete table of the determined partition if a partition table
was found.

### Remark

This script was an assessment during my second semester in IT security master degree program. I know some errors but most time it works fine. 
So, I can't get some warranty about the results!

Use it, try it, modify it as you want. 
If you modify or use my code, it would be nice to know.
