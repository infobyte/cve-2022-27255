#!/usr/bin/python3

import sys
import subprocess
import tempfile

if len(sys.argv) != 3:
    print(f'Usage: {sys.argv[0]} [ghidraLocation] [firmwareImage]')
    sys.exit(0)

filename = sys.argv[2]
ghidraDir = sys.argv[1]

def getEndianness(filename):
    print('Detecting endianess...')
    binwalkOutput = subprocess.run(['binwalk','-Y', filename], capture_output=True).stdout.decode('utf-8')
    endianness = 'big'
    
    if 'little' in binwalkOutput:
        endianness = 'little'
    if 'MIPS' not in binwalkOutput:
        print('Not a MIPS binary, could not detect endianness')
        endianness = ''
    
    return endianness

def getFirmwareBaseAddress(filename, endianness):
    print('Detecting base address...')
    args = ['./firmware_base_address_finder.py', filename]
    if endianness == 'little':
        args.append('little')
    addresses = subprocess.run(args, capture_output=True).stdout.decode('utf-8')
    firmwareBaseIndex = addresses.find('Firmware base:')
    if firmwareBaseIndex == -1:
        print('Could not detect base address')
        return 0
    baseAddressIndex = addresses.find('0x', firmwareBaseIndex)
    baseAddress = int(addresses[baseAddressIndex: baseAddressIndex + 10], 16)
    return baseAddress

def checkFirmware(filename):
    with tempfile.TemporaryDirectory() as tmpdirname:
        # determine endianness and loading address
        endianness = getEndianness(filename)
        if endianness == '':
            return
        print(f'Detected {endianness} endian')
        address = getFirmwareBaseAddress(filename, endianness)
        if address == 0:
            return
        print(f'Detected base address @ {hex(address)}')

        # extract the firmware
        subprocess.run(['binwalk', '-C', tmpdirname, '-e', filename],stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        fileListing = subprocess.run(['find', tmpdirname, '-type', 'f'], capture_output=True).stdout.decode('utf-8')
        originalSquashfsCount = filename.lower().count('squashfs')

        # iterate over all extracted files
        for filename in fileListing.split('\n'):
            filename = filename.strip()
            if filename:
                # skip the ones that are inside a squash fs
                filenameHasExtension = filename.find('.', filename.rfind('/')) != -1
                filenameIsInsideSquashFs = filename.lower().count('squashfs') > originalSquashfsCount
                if filenameHasExtension or filenameIsInsideSquashFs:
                    continue

                # run the ghidra script and report findings
                print(f'Analyzing {filename}...')
                lang = 'MIPS:BE:32:default'
                if endianness == 'little':
                    lang = 'MIPS:LE:32:default'
                argStr = f'{ghidraDir}/support/analyzeHeadless {tmpdirname} tmp -import "{filename}" -processor {lang} -postScript ../ghidra_scripts/firmware_vulnerability_checker.py -loader BinaryLoader -loader-baseAddr {hex(address)}'
                ghidraOutput = subprocess.run(argStr.split(' '), capture_output=True).stdout.decode('utf-8')
                if 'Vulnerable!\n' in ghidraOutput:
                    print(f'Firmware is vulnerable')
                    vulneraleStringLocation = ghidraOutput.find('Vulnerable!\n')
                    print(f'Detected vulnerable call @ 0x{ghidraOutput[vulneraleStringLocation + 12: vulneraleStringLocation + 20]}')
                    return

checkFirmware(filename)
