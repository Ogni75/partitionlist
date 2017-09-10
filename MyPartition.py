# !/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import struct
import binascii
import operator
import stat


"""
Author			:	Ingo Braun
Created			:	19/02/16
Last Modified   :   12/03/16

This module provide functions to interpret the partition system on a device or raw image.
"""

version = "0.5"

# dictonary to decode mbr type
MBRTYPES = {
    "00": "Empty",
    "01": "FAT12,CHS",
    "04": "FAT16 16-32MB,CHS",
    "05": "Microsoft Extended",
    "06": "FAT16 32MB,CHS",
    "07": "NTFS",
    "0b": "FAT32,CHS",
    "0c": "FAT32,LBA",
    "0e": "FAT16, 32MB-2GB,LBA",
    "0f": "Microsoft Extended, LBA",
    "11": "Hidden FAT12,CHS",
    "14": "Hidden FAT16,16-32MB,CHS",
    "16": "Hidden FAT16,32MB-2GB,CHS",
    "18": "AST SmartSleep Partition",
    "1b": "Hidden FAT32,CHS",
    "1c": "Hidden FAT32,LBA",
    "1e": "Hidden FAT16,32MB-2GB,LBA",
    "27": "PQservice",
    "39": "Plan 9 partition",
    "3c": "PartitionMagic recovery partition",
    "42": "Microsoft MBR,Dynamic Disk",
    "44": "GoBack partition",
    "51": "Novell",
    "52": "CP/M",
    "63": "Unix System V",
    "64": "PC-ARMOUR protected partition",
    "82": "Solaris x86 or Linux Swap",
    "83": "Linux",
    "84": "Hibernation",
    "85": "Linux Extended",
    "86": "NTFS Volume Set",
    "87": "NTFS Volume Set",
    "9f": "BSD/OS",
    "a0": "Hibernation",
    "a1": "Hibernation",
    "a5": "FreeBSD",
    "a6": "OpenBSD",
    "a8": "Mac OSX",
    "a9": "NetBSD",
    "ab": "Mac OSX Boot",
    "af": "MacOS X HFS",
    "b7": "BSDI",
    "b8": "BSDI Swap",
    "bb": "Boot Wizard hidden",
    "be": "Solaris 8 boot partition",
    "d8": "CP/M-86",
    "de": "Dell PowerEdge Server utilities (FAT fs)",
    "df": "DG/UX virtual disk manager partition",
    "eb": "BeOS BFS",
    "ee": "EFI GPT Disk",
    "ef": "EFI System Parition",
    "fb": "VMWare File System",
    "fc": "VMWare Swap"
}

# dictonary to decode gpt guid
GPTTYPES = {
    "00000000-0000-0000-0000-000000000000": "GPT, Unused entry",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "IBM-PC",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Windows (EFI)",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows",
    "7412F7D5-A156-4B13-81DC-867174929325": "ONIE",
    "D4E6E2CD-4469-46F3-B5CB-1BFF57AFC149": "ONIE config",
    "9E1A2D38-C612-4316-AA26-8B49521E5A8B": "PReP",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "Windows",
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Windows LDM metadata",
    "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D": "Windows Storage Spaces",
    "37AFFC90-EF7D-4E96-91C3-2D7AE055B174": "IBM GPFS",
    "FE3A2A5D-4F32-41A7-B725-ACCC3285A309": "Chromebook",
    "3CB8E202-3B7E-47DD-8A3C-7FF2A13CFCEC": "ChromeOS root",
    "2E0A753D-9E48-43B0-8337-B15192CB1B5E": "ChromeOS reserved",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "8DA63339-0007-60C0-C436-083AC8230908": "Linux reserved",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "freedesktop.org (Linux)[12][13]",
    "44479540-F297-41B2-9AF7-D131D5F0458A": "Linux x86 root",
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux x86-64 root",
    "B921B045-1DF0-41C3-AF44-4C6F280D3FAE": "Linux ARM64 root",
    "3B8F8425-20E0-4F3B-907F-1A25A76F98E8": "Linux /srv",
    "D3BFE2DE-3DAF-11DF-BA40-E3A556D89593": "Intel-PC",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux",
    "516E7CB4-6ECF-11D6-8FF8-00022D09712B": "FreeBSD",
    "83BD6B9D-7F41-11DC-BE0B-001560B84F0F": "FreeBSD boot",
    "516E7CB5-6ECF-11D6-8FF8-00022D09712B": "FreeBSD swap",
    "516E7CB6-6ECF-11D6-8FF8-00022D09712B": "FreeBSD UFS",
    "516E7CBA-6ECF-11D6-8FF8-00022D09712B": "FreeBSD ZFS",
    "516E7CB8-6ECF-11D6-8FF8-00022D09712B": "FreeBSD Vinum/RAID",
    "85D5E45A-237C-11E1-B4B3-E89A8F7FC3A7": "MidnightBSD",
    "85D5E45E-237C-11E1-B4B3-E89A8F7FC3A7": "MidnightBSD boot",
    "85D5E45B-237C-11E1-B4B3-E89A8F7FC3A7": "MidnightBSD swap",
    "0394EF8B-237E-11E1-B4B3-E89A8F7FC3A7": "MidnightBSD UFS",
    "85D5E45D-237C-11E1-B4B3-E89A8F7FC3A7": "MidnightBSD ZFS",
    "85D5E45C-237C-11E1-B4B3-E89A8F7FC3A7": "MidnightBSD Vinum",
    "824CC7A0-36A8-11E3-890A-952519AD3F61": "OpenBSD",
    "55465300-0000-11AA-AA11-00306543ECAC": "Mac OS X",
    "49F48D32-B10E-11DC-B99B-0019D1879648": "NetBSD",
    "49F48D5A-B10E-11DC-B99B-0019D1879648": "NetBSD FFS",
    "49F48D82-B10E-11DC-B99B-0019D1879648": "NetBSD LFS",
    "2DB519C4-B10F-11DC-B99B-0019D1879648": "NetBSD concatenated",
    "2DB519EC-B10F-11DC-B99B-0019D1879648": "NetBSD encrypted",
    "49F48DAA-B10E-11DC-B99B-0019D1879648": "NetBSD RAID",
    "426F6F74-0000-11AA-AA11-00306543ECAC": "Apple boot",
    "48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS/HFS+",
    "52414944-0000-11AA-AA11-00306543ECAC": "Apple RAID",
    "52414944-5F4F-11AA-AA11-00306543ECAC": "Apple RAID offline",
    "4C616265-6C00-11AA-AA11-00306543ECAC": "Apple Label",
    "5265636F-7665-11AA-AA11-00306543ECAC": "AppleTV Recovery",
    "53746F72-6167-11AA-AA11-00306543ECAC": "Apple Core Storage",
    "6A82CB45-1DD2-11B2-99A6-080020736631": "Solaris",
    "6A85CF4D-1DD2-11B2-99A6-080020736631": "Solaris root",
    "6A898CC3-1DD2-11B2-99A6-080020736631": "Solaris /usr",
    "6A87C46F-1DD2-11B2-99A6-080020736631": "Solaris swap",
    "6A8B642B-1DD2-11B2-99A6-080020736631": "Solaris backup",
    "6A8EF2E9-1DD2-11B2-99A6-080020736631": "Solaris /var",
    "6A90BA39-1DD2-11B2-99A6-080020736631": "Solaris /home",
    "6A9283A5-1DD2-11B2-99A6-080020736631": "Solaris alternate sector",
    "6A945A3B-1DD2-11B2-99A6-080020736631": "Solaris Reserved",
    "6A9630D1-1DD2-11B2-99A6-080020736631": "Solaris Reserved",
    "6A980767-1DD2-11B2-99A6-080020736631": "Solaris Reserved",
    "6A96237F-1DD2-11B2-99A6-080020736631": "Solaris Reserved",
    "6A8D2AC7-1DD2-11B2-99A6-080020736631": "Solaris Reserved",
    "75894C1E-3AEB-11D3-B7C1-7B03A0000000": "HP-UX",
    "E2A1E728-32E3-11D6-A682-7B03A0000000": "HP-UX service",
    "BC13C2FF-59E6-4262-A352-B275FD6F7172": "freedesktop.org[13]",
    "42465331-3BA3-10F1-802A-4861696B7521": "Haiku",
    "BFBFAFE7-A34F-448A-9A5B-6213EB736C22": "ESP, herstellerspezifisch",
    "F4019732-066E-4E12-8273-346C5641494F": "Sony system partition",
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI",
    "024DEE41-33E7-11D3-9D69-0008C781F39F": "MBR partition scheme",
    "21686148-6449-6E6F-744E-656564454649": "BIOS boot partition",
    "4FBD7E29-9D25-41B8-AFD0-062C0CEFF05D": "Ceph",
    "4FBD7E29-9D25-41B8-AFD0-5EC00CEFF05D": "Ceph dm-crypt OSD",
    "45B0969E-9B03-4F30-B4C6-B4B80CEFF106": "Ceph journal",
    "45B0969E-9B03-4F30-B4C6-5EC00CEFF106": "Ceph dm-crypt journal",
    "89C57F98-2FE5-4DC0-89C1-F3AD0CEFF2BE": "Ceph disk in creation",
    "89C57F98-2FE5-4DC0-89C1-5EC00CEFF2BE": "Ceph dm-crypt disk in creation",
    "AA31E02A-400F-11DB-9590-000C2911D1B8": "VMware ESX",
    "9198EFFC-31C0-11DB-8F78-000C2911D1B8": "VMware reserved",
    "9D275380-40AD-11DB-BF97-000C2911D1B8": "VMware kcore crash protection",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": ""
}

# FS signature
# {"Name":name, position:decimalvalue, header:hexvakue, shift:decimalvalue}
VBRHEADER = [

    {"name": "NTFS", "pos": 3, "header": "4e54465320202020", "shift": 0},
    {"name": "EXFAT", "pos": 3, "header": "4558464154202020", "shift": 0},
    {"name": "FAT32", "pos": 82, "header": "4641543332", "shift": 0},
    {"name": "FAT12", "pos": 2, "header": "4641543132", "shift": 0},
    {"name": "FAT16", "pos": 2, "header": "4641543136", "shift": 0},
    {"name": "EXTx", "pos": 56, "header": "53ef", "shift": 1024},
    {"name": "HFSX", "pos": 0, "header": "4858", "shift": 1024},
    {"name": "HFS+", "pos": 0, "header": "482b", "shift": 1024},
    {"name": "HFS", "pos": 0, "header": "4244", "shift": 1024},
    {"name": "ReiserFS", "pos": 34, "header": "526549734572", "shift": 10000},
    {"name": "XFS", "pos": 0, "header": "584653", "shift": 0},
    {"name": "Reiser2FS", "pos": 53, "header": "526549734572324673", "shift": 65535},
    {"name": "JFS", "pos": 0, "header": "4a465331", "shift": 32768},
    {"name": "Linux Swapspace", "pos": 502, "header": "53574150535041434532", "shift": 3584},
    {"name": "unknown", "pos": 0, "header": "", "shift": 0}
]

'''
Filehandling
'''


def openFile(_image):
    """
    Open file; check access and path;
    set global variables to be sure that everything neede is open

    :param _image: Imagefile or device
    :return: true if everything work
    """

    # define global variables
    global file_is_open
    global openedFile

    # try to open file; set global marker 'file_is_open' to true
    try:
        openedFile = open(_image, "rb")
        file_is_open = True
    except IOError as syserr:
        errnote = "({})".format(syserr)
        sys.exit(errnote)

    return True


def closeFile():
    """closes the given file _image; return true if closed"""

    # define variables
    global file_is_open

    # check if file is open
    if file_is_open:
        # try to close file and unset file_is_open
        try:
            openedFile.close()
            file_is_open = False
        except IOError as syserr:
            errnote = "({})".format(syserr)
            sys.exit(errnote)

    return True


def readBinary(_position, _length):
    """read binary from file from _position with _length and return the value

    :param _position: position in bytes
    :param _length: length in bytes
    :return: read value
    """
    global file_is_open

    # check if file is open
    if file_is_open:
        # read length at position
        try:
            openedFile.seek(_position)
            value = openedFile.read(_length)
        except IOError as syserr:
            # feedback variable is set and file isn't open; which should never happen
            closeFile()
            errnote = "({})".format(syserr)
            sys.exit(errnote)

        return value
    else:
        # end script if file isn't open
        errnote = "No file to read is open."
        sys.exit(errnote)


def getdevicesize(_image):
    """
    check devicesize
    :param _image: raw image name or block device
    :return: devicesize
    """
    f = os.open(_image, os.O_RDONLY)
    try:
        _size = os.lseek(f, 0, os.SEEK_END)
        return _size
    finally:
        os.close(f)


def isblockdevice(_image):
    """
    check if _image is a block device
    :param _image: raw image name or block device
    :return: boolean
    """
    # try to read the inode of file
    try:
        _imagemode = os.lstat(_image).st_mode
    except OSError:
        return False
    else:
        # checks inode for blockdevice
        return stat.S_ISBLK(_imagemode)


def checkfile(_image):
    """
    check image file/device if exist and readable etc
    :param _image: raw image name or block device
    :return: _file_is_ok, _errnote, _devicesize
    """

    _errnote = ""
    _devicesize = 0
    _file_is_ok = True

    # check if path exists
    if not os.path.exists(_image):
        _errnote = "({})".format("'" + _image + "' not exists.")
        _file_is_ok = False

    # check if file
    elif os.path.isdir(_image):
        _errnote = "({})".format("'" + _image + "' is a path. Please specify the file for analysis.")
        _file_is_ok = False
    # or only path
    elif not os.path.isfile(_image):
        # check if file and not blockdevice
        if not isblockdevice(_image):
            _errnote = "({})".format("'" + _image + "' is not a valid file/device. Please specify the filename.")
            _file_is_ok = False
    # path read access
    elif not os.access(_image, os.R_OK):
        _errnote = "({})".format("Permission denied. Please change the permission to read this file or device!")
        _file_is_ok = False
    # get devicesize
    if _file_is_ok:
        try:
            _devicesize = getdevicesize(_image)
            if _devicesize < 512:
                _errnote = "({})".format("File is to small. No boot record possible!")
                _file_is_ok = False
        except:
            if isblockdevice(_image):
                _errnote = "({})".format(
                        "Error while opening block device. It's not possible to read file size. You need to be root to read block devices.")
            else:
                _errnote = "({})".format("Error while opening imagefile. It's not possible to read file size.")
            _file_is_ok = False

    if not _file_is_ok:
        return False, _errnote, _devicesize

    return (_file_is_ok, _errnote, _devicesize)


'''
                Partitioning System
                    MBR/GPT
'''


def parsePartitionTable(_image):
    """Mainfunction to parse the partitiontable.

    :param _image: The file (image/device) to parse
    :return: True if partitiontable; False if VBR

    """
    # check if given file is ok
    (_file_is_ok, _error, _devicesize) = checkfile(_image)
    if not _file_is_ok:
        sys.exit(_error)

    # get the partitionscheme to start the matching function
    _PartitionScheme = getPartitionScheme(_image, _devicesize)
    # create partitintable for gpt
    if _PartitionScheme == "GPT":
        _PartitionTable = parseGPT(_devicesize)
    # create partitintable for mbr
    elif _PartitionScheme == "MBR":
        _PartitionTable = parseMBR(_devicesize)
    # create partitintable for hybrid
    elif _PartitionScheme == "Hybrid":

        _PartitionTable = parseMBR(_devicesize)
        _PartitionTable = getUnallocated(_PartitionTable, _devicesize)
        printTable2Screen(_image, _PartitionScheme, _PartitionTable, _devicesize, _part="MBR part")

        _hybridTable = _PartitionTable

        _PartitionTable = parseGPT(_devicesize)
        _PartitionTable = getUnallocated(_PartitionTable, _devicesize)
        printTable2Screen(_image, _PartitionScheme, _PartitionTable, _devicesize, _part="GPT part")

        _hybridTable += _PartitionTable

        return True, _hybridTable
    # check if vbr and print vbr info
    else:
        vbr = checkvbr(_image, _devicesize, _PartitionScheme)
        return False, vbr
    # calculate unalocated for gpt and mbr
    _PartitionTable = getUnallocated(_PartitionTable, _devicesize)
    # print table
    printTable2Screen(_image, _PartitionScheme, _PartitionTable, _devicesize)

    closeFile()

    return True, _PartitionTable


def getPartitionScheme(_image, _devicesize):
    """Check the partitioning scheme of the give file/device

    :param _image: Filename
    :return: GPT/MBR partionscheme
    """

    # define variables

    _magic_number_check = False
    _protective_mbr_check = False
    _partitionScheme = ""

    _sectorsize = _devicesize / 512

    # open file
    openFile(_image)
    # check if vbr then return
    _vbrcheck = getPartitionFS(0)
    _partitionScheme = _vbrcheck
    if not _vbrcheck == "unknown":
        closeFile()
        return _partitionScheme

    # read first sector
    sector = readBinary(0, 512)

    # check if magic number "55aa" exist
    _magic_number_check = struct.unpack_from('<H', readBinary(510, 2))[0] == 0xaa55
    if _magic_number_check:

        _partitionScheme = "MBR"

        # check if there is a protective mbr AND the "EFI PART" signature in second sector
        _protective_mbr_check = struct.unpack_from('<B', readBinary(450, 1))[0] == 0xee

        if _protective_mbr_check and readBinary(512, 8) == "EFI PART":
            _partitionScheme = "GPT"

        if _protective_mbr_check and struct.unpack_from('<B', readBinary(466, 2))[0] != 0x00:
            _partitionScheme = "Hybrid"

    else:

        closeFile()

    return _partitionScheme


def parseMBR(_devicesize):
    """Function to parse the MBR. It's a subroutine of parsePartitionTable(). Its needed that this start from
    parsePartitionTable() to ensure, that the file is open and the right scheme will interpreted
    :return: PartitionTable
    """

    # define variables
    PartitionTable = []
    i = 0
    # while all primary partitions are read
    while i < 4:
        # read partition entry X
        _partitionInfo = readBinary(446 + (16 * i), 16)
        (_partitiontype, _partitionstart, _partitionlength) = struct.unpack_from("<4xs3xLL", _partitionInfo)

        # counter for actual partition nr
        _nextnr = len(PartitionTable)
        # write actual entry to dictonary
        _partition = {}
        _partition["nr"] = _nextnr
        _partition["typ"] = binascii.hexlify(_partitiontype)
        _partition["typtext"] = parseFSID(_partition["typ"], "MBR")
        _partition["start"] = _partitionstart
        _partition["length"] = _partitionlength
        _partition["signature"] = getPartitionFS(_partition["start"])

        # change typ if extended partition
        if _partition["typ"] == "05":
            _partition["signature"] = "1. EBR"
        # write actual entry in list
        PartitionTable.append(_partition)
        # if extended use function and end while loop
        if _partition["typ"] == "05":
            parseEBR(PartitionTable, _partitionstart, _devicesize)
            i = 3
        # del entry and end while loop if entry with zero follow
        if _partition["typ"] == "00" and _partition["start"] == 0 and _partition["length"] == 0:
            del (PartitionTable[i])
            i = 3

        i += 1

    # add Bootrecord as allocated
    _partition = {}
    _partition["nr"] = "-"
    _partition["typ"] = "--"
    _partition["typtext"] = "Bootrecord"
    _partition["start"] = 0
    _partition["length"] = 1
    _partition["signature"] = "No signature"
    PartitionTable.append(_partition)

    return PartitionTable


def parseEBR(PartitionTable, _startsector, _devicesize):
    """	Function to parse the EBR. It's a subroutine from parseMBR().	Its needed to start this only from parseMBR()
    to ensure, that the file is open and the right scheme will interpreted
    :param _startsector:
    :return: PartitionTable
    """

    # define variables
    _nextEBRStart = 0
    _EBRcount = 1
    i = True
    # while true read logical partition entry and the following next extended entry
    while i == True:

        if _startsector + _nextEBRStart > _devicesize / 512:
            return PartitionTable

        # read logical partition entry X
        _partitionInfo = readBinary((_startsector + _nextEBRStart) * 512 + 446, 16)
        _nextnr = len(PartitionTable)

        (_partitiontype, _partitionstart, _partitionlength) = struct.unpack_from("<4xs3xLL", _partitionInfo)
        # add partition entry to partition dictonary
        _partition = {}
        _partition["nr"] = _nextnr
        _partition["typ"] = binascii.hexlify(_partitiontype)
        _partition["typtext"] = parseFSID(_partition["typ"], "MBR")
        _partition["start"] = _partitionstart + _startsector + _nextEBRStart
        _partition["length"] = _partitionlength
        _partition["signature"] = getPartitionFS(_partition["start"])
        # add dictonary to partition table list
        PartitionTable.append(_partition)

        # read extended entry and link to next ebr
        _partitionInfo = readBinary((_startsector + _nextEBRStart) * 512 + 470, 8)
        (_nextEBRStart, _nextEBRLength) = struct.unpack_from("<LL", _partitionInfo)
        # counter for ebr
        _EBRcount += 1
        # add ebr to partition table dictonary
        _partition = {}
        _partition["nr"] = _nextnr + 1
        _partition["typ"] = "05"
        _partition["typtext"] = "Microsoft Extended"
        _partition["start"] = _nextEBRStart + _startsector
        _partition["length"] = _nextEBRLength
        _partition["signature"] = str(_EBRcount) + ". EBR"
        # add partiotion partition table list if not 0 entry; else end while loop
        if _nextEBRStart != 0:
            PartitionTable.append(_partition)
        else:
            i = False

    return PartitionTable


def parseGPT(_devicesize):
    """	Function to parse the GPT. It's a subroutine of parsePartitionTable(). Its needed that this start from
    parsePartitionTable() to ensure, that the file is open and the right scheme will interpreted

    :return: PartitionTable
    """

    # define variables
    PartitionTable = []
    _gptHeaderPos = 512
    _PartTablePosInfo = 72
    _PartEntryLengthInfo = 84
    _sectorsize = (_devicesize) / 512
    i = True
    h = 0

    # get gpt start of partition table
    (_PartTableStart, _PartEntryLength) = struct.unpack_from("<Q4xi", readBinary((_gptHeaderPos + _PartTablePosInfo), 16))

    # read while i is true
    while i:
        # read partition GUID
        _partEntry = readBinary(((_PartTableStart * 512) + (h * _PartEntryLength)), 16)
        _raw_guid = struct.unpack_from(">4s2s2s2s6s", _partEntry)
        # read partiton entry
        _partEntry = readBinary(((_PartTableStart * 512) + (h * _PartEntryLength) + 32), 16)
        (_partitionstart, _partitionend) = struct.unpack_from("<QQ", _partEntry)
        # add partition entry to partition dictonary
        _partition = {}
        _partition["nr"] = h
        _partition["typ"] = buildGUID(_raw_guid)
        _partition["typtext"] = parseFSID(_partition["typ"], "GPT")
        _partition["start"] = _partitionstart
        _partition["length"] = _partitionend - _partitionstart + 1
        _partition["signature"] = getPartitionFS(_partition["start"])
        # add partition to PartitionTable list
        PartitionTable.append(_partition)

        h += 1
        if _partition["typ"] == "00000000-0000-0000-0000-000000000000" and _partitionstart == 0 and _partitionend == 0:
            del (PartitionTable[h - 1])
            i = False

        if h == 128:
            i = False

    # add partition table as allocated
    _partition = {}
    _partition["nr"] = "-"
    _partition["typ"] = "--"
    _partition["typtext"] = "GUID Partition Table"
    _partition["start"] = 1
    _partition["length"] = 1 + int((128 * len(PartitionTable) / 512)) + ((128 * len(PartitionTable) / 512) > 0)
    _partition["signature"] = "No signature"
    PartitionTable.append(_partition)

    # add Bootrecord as allocated
    _partition = {}
    _partition["nr"] = "-"
    _partition["typ"] = "--"
    _partition["typtext"] = "Bootrecord"
    _partition["start"] = 0
    _partition["length"] = 1
    _partition["signature"] = "No signature"
    PartitionTable.append(_partition)

	# check if gptbackup at end of image; than allocate this sector
	
    if checkGPTcopy(_sectorsize-1):
        _partition = {}
        _partition["nr"] = "-"
        _partition["typ"] = "--"
        _partition["typtext"] = "EFI Backup"
        _partition["start"] = _sectorsize-1
        _partition["length"] = 1
        _partition["signature"] = "No signature"
        PartitionTable.append(_partition)

    return PartitionTable


'''
            Filesystem
'''


def parseFSID(_partitioncode, _partitionscheme, _fs=None):
    """	Search the given ID in the partitiondictonary at start of module
    :param _partitioncode: GUID from GPT or ID from MBR
    :param _partitionscheme: MBR/GPT
    :return: _fs: Filesystemname
    """
    _fs = ""

    if _partitionscheme == "GPT":
        if _partitioncode not in GPTTYPES:
            _fs = "Unknown FS GUID"
        else:
            _fs = GPTTYPES[_partitioncode]

    if _partitionscheme == "MBR":
        if _partitioncode not in MBRTYPES:
            _fs = "Unknown FS ID"
        else:
            _fs = MBRTYPES[_partitioncode]

    return _fs


def getPartitionFS(_startsector):
    """	verify partition signature and compares with known Filesystem
    :_startsector: startsector of partition
    :return: Name of found filesystem or unknown
    """

    i = 0
    _Filesystem = ""
    # loop for every entry in VBR Header list
    while i != len(VBRHEADER):

        _isheader = False
        _readpos = 0
        # declare actual variables on which position, which header could found 
        _shift = VBRHEADER[i]["shift"]
        _header = VBRHEADER[i]["header"]
        _pos = VBRHEADER[i]["pos"]
        _length = len(str(_header))
        #calculate position
        _readpos = (_startsector) * 512 + _pos + _shift
        #read position
        _partitionInfo = readBinary(_readpos, _length)

        structstring = "<" + str(_length / 2) + "s"
        #check if header is found; then break and return the filesystem
        try:
                _isheader = binascii.hexlify(struct.unpack_from(structstring, _partitionInfo)[0]) == _header
        except:
            _Filesystem = "unknown"
            return (_Filesystem)
        if _isheader:
            _Filesystem = VBRHEADER[i]["name"]
            return (_Filesystem)
        #else, if the actual loop filesystem not found, use next entry to compare 
        i += 1

    return _Filesystem


def checkvbr(_image, _devicesize, _fs):
    """
    check if vbr in first sectors and verify filesystem
    :param _image:
    :param _fs : found filesystem
    :param _devicesize:
    :return:
    """

    print "\nPartitionlist"
    print "============="
    print "\nFile: " + _image + "\n"
    print "Unknown Partition Table"
    print "Device Size: " + str(_devicesize) + " Bytes / " + str(_devicesize / 512) + " Sectors"

    print "\nNo or unknown partition table found. Parsing is not possible"
    print "Try to parse the first sectors in image as VBR"
    print "-------------------------------------"
    if _fs != "unknown":
        print "{0} filesystem found.".format(_fs)
        print "You have to parse VBR manually\n"
    else:
        print "No filesystem found"

    return _fs


'''
            Calculating Unallocated
'''


def getUnallocated(_partitionTable, _devicesize):
    """ find unallocated space in partitiontable
    :param _partitionTable:
    :param _devicesize:
    :return: _partitionTable, sorted with unallocated spaces
    """

    i = 0
    Unallocated = []
    # sort partition table by field "start"
    _partitionTable = sorted(_partitionTable, key=operator.itemgetter('start'))

    _sectorsize = _devicesize / 512
    _end = 0
    #calculate the unallocated space
    while i < len(_partitionTable):
        # if there could be find a gap between the end of partition and beginning of new partition
        if _end < _partitionTable[i]['start'] - 1:
			#new entry for unallocated in partition table
            _unallocated = {}
            _unallocated['nr'] = "-"
            _unallocated['start'] = int(_end)
            _unallocated['length'] = int(_partitionTable[i]['start'] - _end)
            _unallocated['typ'] = "--"
            _unallocated['typtext'] = "Unallocated"
            _unallocated["signature"] = "No signature"

            Unallocated.append(_unallocated)
        #save the end of last entry for next loop round
        if i < len(_partitionTable):
            _end = _partitionTable[i]['start'] + _partitionTable[i]['length']
            #if entry is extended, only use one sector 
            if _partitionTable[i]['typ'] == "05":
                _end = _partitionTable[i]['start'] + 1
        i += 1

    # if last partition entry is reached; calculate unallocated until device end
    if (_partitionTable[len(_partitionTable) - 1]['start'] + _partitionTable[len(_partitionTable) - 1][
        'length']) < _sectorsize:
        _unallocated = {}
        _unallocated['start'] = int((_partitionTable[len(_partitionTable) - 1]['start'] +
                                     _partitionTable[len(_partitionTable) - 1]['length']))
        _unallocated['length'] = int(_sectorsize - _unallocated['start'])
        _unallocated['nr'] = "-"
        _unallocated['typ'] = "--"
        _unallocated['typtext'] = "Unallocated"
        _unallocated["signature"] = "No signature"

        Unallocated.append(_unallocated)

    _newpartitionTable = _partitionTable + Unallocated
    _partitionTable = sorted(_newpartitionTable, key=operator.itemgetter('start'))

    return _partitionTable


'''
        Helper
'''


def buildGUID(_hextuple):
    """	buiding guid from hexvalue
    :param _hextuple: tuple with (00000000)-(0000)-(0000)-(0000)-(000000000000)
    :return: GUID
    """

    GUID = ""
    i = 0

    while i < 3:
        GUID += LE((binascii.hexlify(_hextuple[i]))) + "-"
        i += 1
    GUID += binascii.hexlify(_hextuple[3]) + "-" + binascii.hexlify(_hextuple[4])

    return GUID.upper()


def LE(_string):
    """turns pairs of characters from big to little endian
    ---only for building guid---
    :param _string: string to turn
    :return: turned string"""

    _newstring = ""
    i = 0
    if len(_string) % 2 != 0:
        _string = "0" + _string
    while i < len(_string):
        _newstring = _newstring + _string[-(i + 2)] + _string[-(i + 1)]
        i += 2

    return _newstring


def checkGPTcopy(_devicesize):
    """
    Check if backupcopy of EFI found
    :param:_devicesize: size in sector
    :return: boolean
    """
    # return true if backup is found
    return readBinary(_devicesize * 512, 8) == "EFI PART"



'''
                    Output
'''


def printTable2Screen(_image, _partitionscheme, _partitionTable, _devicesize, _part=""):
    """
    This function print the calculated and verified partitionsystem
    :param _image:
    :param _image:              Imagename for textual output_partitionscheme:
    :param _partitionscheme:    Partitionscheme for textual output_partitionTable:
    :param _partitionTable:     The found partitiontable_devicesize:
    :param _devicesize:         size of device in Bytes_part:
    :return: True; print table to screen:
    """

    line = '='
    head = '{:}  {:}  {:}  {:}  {:}  {:}'
    table = '{:}  {:}  {:}  {:}  {:}  {:}  {:}'

    if _partitionscheme == "MBR":
        head = "{:<6}  {:>10}  {:>12}  {:>7} {:>7} {:>28}".format("Number", "Start", "Length", "Type", "Name",
                                                                  "Signature")
        line *= 85
        table = "{:<2}: ({:>})  {:>012d}  {:>012d}  {:<2}  {:<20}  {:>20}"

    elif _partitionscheme == "GPT":
        head = "{:<6}  {:>10}  {:>12}  {:>23} {:>25} {:>28}".format("Number", "Start", "Length", "GUID", "Name",
                                                                    "Signature")
        line *= 119
        table = "{:<2}: ({:>})  {:>012d}  {:>012d}  {:<38}  {:<20}  {:>20}"

    elif _partitionscheme == "Hybrid":
        head = "{:<6}  {:>10}  {:>12}  {:>23} {:>25} {:>28}".format("Number", "Start", "Length", "GUID", "Name",
                                                                    "Signature")
        line *= 119
        table = "{:<2}: ({:>})  {:>012d}  {:>012d}  {:<38}  {:<20}  {:>20}"

    print "\nPartitionlist"
    print "============="
    print "\nFile: " + _image + "\n"
    print _partitionscheme, "Partition Table", _part
    print "Device Size: " + str(_devicesize) + " Bytes / " + str(_devicesize / 512) + " Sectors"
    print head.format("Number", "Start", "Length", "Type", "Name", "Signature")
    print line

    i = 0

    while i != len(_partitionTable):
        print table.format(i, _partitionTable[i]["nr"], _partitionTable[i]["start"], _partitionTable[i]["length"],
                           "(" + _partitionTable[i]["typ"] + ")", _partitionTable[i]["typtext"],
                           _partitionTable[i]["signature"])

        i += 1

    return

if __name__ == "__main__":
    print"\nModule not executeable!\n"
    print"Please use the script 'pl.py' or start analyzing with integrate the mainfunction 'parsePartitionTable(_image)'"