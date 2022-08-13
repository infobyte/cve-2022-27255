# Data flow-based analysis for finding vulnerable function calls

#@author ogalland, ogianatiempo
#@category Analysis.MIPS
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.util import DefinedDataIterator
from ghidra.program.model.symbol import DataRefType
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

class VulnCallFinder():
	__vulnCalls = []
	__vulnFns = []

	def printVulnCalls(self):
		print('Found ' + str(len(self.__vulnCalls)) + ' potentially vulnerable calls!')
		print("Calls:")
		for call in self.__vulnCalls:
			print(call)
		print("\n\n")
		print("Functions:")
		for call in self.__vulnFns:
			print(call.getEntryPoint())

	def process(self, callAddr, fnAddr):
		ifc = DecompInterface()
		ifc.openProgram(currentProgram)
		ifc.setOptions(DecompileOptions())
		monitor = ConsoleTaskMonitor()

		fun = getFunctionBefore(callAddr)

		dec = ifc.decompileFunction(fun, 60, monitor)
		high_func = dec.getHighFunction()
		if high_func:
			opiter = high_func.getPcodeOps()
			while opiter.hasNext():
				op = opiter.next()
				mnemonic = str(op.getMnemonic())
				if mnemonic == "CALL" and op.getInputs()[0].getAddress() == fnAddr and op.getSeqnum().getTarget() == callAddr: # is a the target call to fnAddr
					if self.__isStackDerived(op.getInputs()[1]) and not op.getInputs()[2].getAddress().getAddressSpace().isMemorySpace():
						self.__vulnCalls.append(callAddr)
						self.__vulnFns.append(fun)
						
	def __getRegisterName(self, varnode):
		reg = currentProgram.getRegister(varnode.getAddress(), varnode.getSize())
		if not reg:
			return None
		return reg.getName()

	def __isStackDerived(self, varnode):
		ops = [varnode.getDef()]
		i = 0
		while len(ops) > 0:
			op = ops.pop()
			if not op:
				continue
			elif any(self.__getRegisterName(input) == 'sp' for input in op.getInputs()):
				return True
			elif any(input.getAddress().getAddressSpace().isStackSpace() for input in op.getInputs()):
				return True
			for input in op.getInputs():
				if input.isRegister() and input.getDef() not in ops:
					ops.append(input.getDef())
			i += 1
			if i > 1000:
				break
		return False
			

finder = VulnCallFinder()

# modify this address to look for other function calls
strcpyAddr = getAddress(0x801133E0)

calls = [ref.fromAddress for ref in getReferencesTo(strcpyAddr)]

for call in calls:
	finder.process(call, strcpyAddr)

finder.printVulnCalls()
