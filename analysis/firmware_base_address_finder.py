#!/usr/bin/python3
import sys
from capstone import *
from binascii import hexlify

if len(sys.argv) < 2:
    print(f'Usage: {sys.argv[0]} firmwareImage [little]')
    print(f'\tSelect a file to analyse, and optionally set endianness to "little"')
    sys.exit(0)

endian = CS_MODE_BIG_ENDIAN
if len(sys.argv) > 2 and sys.argv[2] == 'little':
    endian = CS_MODE_LITTLE_ENDIAN

code = b''
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + endian)
md.skipdata = True
with open(sys.argv[1], 'rb') as f:
    code = f.read()

str1 = code.find(b'decompressing kernel:\n')
str2 = code.find(b'done decompressing kernel.\n')
str3 = code.find(b'start address: 0x%08x')
limit = str1

instructions = [i for i in md.disasm(code, 0) if i.address < limit]

class MIPSInstruction():
    def __init__(self, capstoneInstruction):
        self.__args = capstoneInstruction.op_str.split(', ')
        self.__mnemonic = capstoneInstruction.mnemonic
    def modifiesArg0(self):
        # This list is not exhaustive, we're only focusing on the instructions we've
        # already seen in one of the bootloaders
        return self.__mnemonic in ['move', 'addi', 'addiu', 'ori', 'lui']
    def argCount(self):
        return len(self.__args)
    def arg(self, i):
        assert i < self.argCount()
        return self.__args[i]
    def args(self):
        return self.__args
    def mnemonic(self):
        return self.__mnemonic

class MIPSEmu():
    def __init__(self):
        self.__regs = {'$zero':0,'$at':0,'$v0':0,'$v1':0,'$a0':0,'$a1':0,'$a2':0,'$a3':0,'$t0':0,'$t1':0,'$t2':0,'$t3':0,'$t4':0,'$t5':0,'$t6':0,'$t7':0,'$s0':0,'$s1':0,'$s2':0,'$s3':0,'$s4':0,'$s5':0,'$s6':0,'$s7':0,'$t8':0,'$t9':0,'$k0':0,'$k1':0,'$gp':0,'$sp':0,'$s8':0,'$ra':0,'$sr':0,'$lo':0,'$hi':0,'$bad':0,'$cause':0,'$pc':0,'$fsr':0,'$fir': 0, '$fp': 0}
    def parseInstruction(self, instruction):
        # opcode val0, val1, val2
        opcode = instruction.mnemonic()
        if opcode == 'move':
            dstReg = instruction.arg(0)
            val1 = self.register(instruction.arg(1))
            self.register(dstReg, val1)
        if opcode == 'lui':
            dstReg = instruction.arg(0)
            val1 = int(instruction.arg(1), 0)
            self.register(dstReg, val1 << 16)
        if opcode in ['addi', 'addiu', 'ori']:
            dstReg = instruction.arg(0)
            val1 = self.register(instruction.arg(1))
            val2 = int(instruction.arg(2), 0)
            if opcode == 'ori':
                self.register(dstReg, (val1 | val2) & 0xffffffff)
            else:
                self.register(dstReg, (val1 + val2) & 0xffffffff)
    def register(self, regId, value=None):
        if value:
            assert regId in self.__regs
            self.__regs[regId] = value
        else:
            assert regId in self.__regs
            return self.__regs[regId]

addresses = []
lastWasJal = False
a0ModifiedSinceLastJal = True
mipsEmu = MIPSEmu()
for i in instructions:
    ins = MIPSInstruction(i)
    mipsEmu.parseInstruction(ins)
    if ins.argCount() > 0 and ins.arg(0) == '$a0' and ins.modifiesArg0():
        a0ModifiedSinceLastJal = True
    if lastWasJal:
        # we only look for the value of $a0 after the jal instruction
        # because of MIPS's delay slot
        if a0ModifiedSinceLastJal:
            addresses.append(mipsEmu.register('$a0'))
        a0ModifiedSinceLastJal = False
    lastWasJal = ins.mnemonic() == 'jal'

for i in range(len(addresses) - 3):
    firstA0 = addresses[i]
    secondA0 = addresses[i + 1]
    thirdA0 = addresses[i + 2]
    fourthA0 = addresses[i + 3]
    if (thirdA0 - firstA0 == str2 - str1) and (fourthA0 - firstA0 == str3 - str1):
        str1Addr = firstA0
        print('Found base addresses candidates!')
        print(f'\tBootloader base: {hex(str1Addr - str1)}')
        print(f'\tFirmware base: {hex(0x80000000 | (secondA0 & 0x0fffffff))}')
