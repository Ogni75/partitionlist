#!/usr/bin/python
# -*- coding: utf-8 -*-

import MyPartition
import sys
import getopt

version = "0.5"


# _outputfile=""

def printVersion():
    '''
    print the actual version of the script
    :return: nothing
    '''
    print"pl.py Version\t\t:", version
    print"MyPartition.py Version\t:", MyPartition.version
    print"\n"



def start_parsing(_image):
    '''
    calls the parsing functions from modul
    :param _image:
    :return: PartitionTable
    '''

    (hit, PartitionTable) = MyPartition.parsePartitionTable(_image)

    #  No Partitiontable found
    if not hit:
        sys.exit(1)

    # Partitiontable found
    sys.exit(0)


def usage():
    '''
    Info for usage of the tool
    :return: nothing
    '''
    print "pl.py -i <rawimage>       Start parsing the imagefile"
    print "                 -v                  ScriptVersion"
    print "                 -h                  HelpScreen\n"


def help():
    '''
    Helpfunction; explains workflow and shows usage
    :return:
    '''

    printVersion()

    print "This python script try to parse imagefiles or devices. \n" \
          "Parsing is possible, if you give the path to imagefile/device \n" \
          "as the -i option. Known formats are only raw images or if using \n" \
          "linux or mac os raw devices too. If you are using windows a analyze of \n" \
          "rawdevices isn't possible. Same applies to later explained partition \n" \
          "analyzes."
    print "\n\nWorking method:"
    print "First the script check if a filesystem is present in the first sectors. It checks \n" \
          "for known filesystems to exclude that there's a VBR at this position. Than the script\n" \
          "read the first two sector and try to interpret the partitioning scheme with finding \n" \
          "the magic number '55 AA' for existing MBR. A second test checks if the 'EFI PART' Header\n" \
          "for GPT scheme can find in this area. The third test to determine the partitioning scheme\n" \
          "checks if there it's a hybrid boot sector.\n"
    print "Knowing the scheme, the script try to interpret the whole partition table. After finding\n" \
          "the partition position, the script try to verify the found partition with the signatures\n" \
          "in VBR. Additionally the script calculate the unallocated space between found partitions\n"
    print "The output should represent a complete table of the determined partition if a partition table\n" \
          "was found.\n\n"

    usage()


def main():
    '''
    checking startoptions and call the needed function
    :return:
    '''

    image = None

    try:
        opt, arg = getopt.getopt(sys.argv[1:], "vhi:")#, ["version", "help", "image="])
    except getopt.GetoptError, errnote:
        sys.exit(errnote)
    for o, a in opt:
        if o in ("-h"):
            help()
            sys.exit(0)
        elif o in ("-v"):
            printVersion()
            sys.exit(0)
        elif o in ("-i"):
            image = a
            start_parsing(image)
        else:
            errnote = "Unknown option \n"
            usage()
            sys.exit(errnote)

    if image == None:
        usage()


# get started
if __name__ == "__main__":
    main()
