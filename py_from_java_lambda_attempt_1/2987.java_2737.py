Here is the translation of the Java code into Python:

```Python
import ghidra.app.script.GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.data import Data
from ghidra.program.model.listing import Listing, InstructionIterator
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.symbol import SymbolTable

class CompareAnalysisScript(GhidraScript):
    def run(self) -> None:
        if self.currentAddress is None:
            print("No Location.")
            return
        
        otherProgram = askProgram("Choose a program to compare to")
        if otherProgram is None:
            return
        print("\n\n****** COMPARING FUNCTIONS:\n")
        self.compareFunctions(otherProgram)
        print("\n\ntaxxxx COMPARING STRINGS:\n")
        self.compareStrings(otherProgram)
        print("\n\ntaxxxx PERCENT ANALYZED COMPARE SUMMARY:\n")
        self.reportPercentDisassembled(self.currentProgram)
        self.reportPercentDisassembled(otherProgram)
        print("\n\ntaxxxx COMPARING SWITCH TABLES:\n")
        self.compareSwitchTables(otherProgram)
        print("\n\ntaxxxx COMPARING NON-RETURNING FUNCTIONS:\n")
        self.compareNoReturns(otherProgram)
        print("\n\ntaxxxx COMPARING ERRORS:\n")
        self.compareErrors(otherProgram)

    def compareFunctions(self, otherProgram: Program) -> None:
        currentFunctionManager = self.currentProgram.getFunctionManager()
        numMissingFuncs = 0
        numFuncsInCurrentProg = 0

        print("Iterating through functions in " + self.currentProgram.getName())
        functionIterator = self.currentProgram.getListing().getFunctions(self.currentProgram.getMinAddress(), True)
        while functionIterator.hasNext() and not monitor.isCancelled():
            func = functionIterator.next()
            numFuncsInCurrentProg += 1
            address = func.getBody().getMinAddress()
            otherFunction = currentFunctionManager.getFunctionAt(address)
            if otherFunction is None:
                numMissingFuncs += 1
                print(numMissingFuncs + ": Missing function in " + otherProgram.getName() + " at " + str(address))

        print("Iterating through functions in " + otherProgram.getName())
        numMissingFuncs2 = 0
        numFuncsInOtherProg = 0
        functionIterator = otherProgram.getListing().getFunctions(otherProgram.getMinAddress(), True)
        while functionIterator.hasNext() and not monitor.isCancelled():
            func = functionIterator.next()
            numFuncsInOtherProg += 1
            address = func.getBody().getMinAddress()
            otherFunction = currentFunctionManager.getFunctionAt(address)
            if otherFunction is None:
                numMissingFuncs2 += 1
                print(numMissingFuncs2 + ": Missing function in " + self.currentProgram.getName() + " at " + str(address))

        print("\n\ntaxxxx FUNCTION COMPARE SUMMARY:\n")
        print("There are " + str(numFuncsInCurrentProg) + " functions in " + self.currentProgram.getName() +
              " and " + str(numFuncsInOtherProg) + " functions in " + otherProgram.getName())
        print("There are " + str(numMissingFuncs) + " functions missing in " + otherProgram.getName() + 
              " that are in " + self.currentProgram.getName())
        print("There are " + str(numMissingFuncs2) + " functions missing in " + self.currentProgram.getName() +
              " that are in " + otherProgram.getName())

    def reportPercentDisassembled(self, prog: Program) -> None:
        programName = prog.getDomainFile().getName()
        execMemSet = prog.getMemory().getExecuteSet()

        numPossibleDis = 0
        instructionIterator = prog.getListing().getInstructions(execMemSet, True)
        instCount = 0
        while instructionIterator.hasNext():
            inst = instructionIterator.next()
            instCount += len(inst.getBytes())
        dataIterator = prog.getListing().getData(execMemSet, True)
        dataCount = 0
        while dataIterator.hasNext():
            data = dataIterator.next()
            if data.isDefined():
                dataCount += len(data.getBytes())

        total = instCount + dataCount
        if numPossibleDis != 0:
            coverage = (total / numPossibleDis) * 100
            print(programName + ": " + str(coverage) + "% disassembled.")

    def compareStrings(self, otherProgram: Program) -> None:
        currentListing = self.currentProgram.getListing()
        dataIterator = currentListing.getDefinedData(self.currentProgram.getMinAddress(), True)

        numMissingStrings = 0
        numStringsInCurrentProg = 0

        print("Iterating through strings in " + self.currentProgram.getName())
        while dataIterator.hasNext() and not monitor.isCancelled():
            data = dataIterator.next()
            if isString(data.getMnemonicString()):
                address = data.getAddress()
                numStringsInCurrentProg += 1
                otherData = otherListing.getDataAt(address)
                if otherData is None or not isString(otherData.getMnemonicString()):
                    numMissingStrings += 1
                    print(numMissingStrings + ": Missing string in " + otherProgram.getName() + " at " + str(address))

        dataIterator = otherListing.getDefinedData(otherProgram.getMinAddress(), True)

        numMissingStrings2 = 0
        numStringsInOtherProg = 0

        while dataIterator.hasNext() and not monitor.isCancelled():
            data = dataIterator.next()
            if isString(data.getMnemonicString()):
                address = data.getAddress()
                numStringsInOtherProg += 1
                otherData = currentListing.getDataAt(address)
                if otherData is None or not isString(otherData.getMnemonicString()):
                    numMissingStrings2 += 1
                    print(numMissingStrings2 + ": Missing string in " + self.currentProgram.getName() + " at " + str(address))

        print("\n\ntaxxxx STRING COMPARE SUMMARY:\n")
        print("There are " + str(numStringsInCurrentProg) + " strings in " + self.currentProgram.getName() +
              " and " + str(numStringsInOtherProg) + " strings in " + otherProgram.getName())
        print("There are " + str(numMissingStrings) + " strings missing in " + otherProgram.getName() +
              " that are in " + self.currentProgram.getName())
        print("There are " + str(numMissingStrings2) + " strings missing in " + self.currentProgram.getName() +
              " that are in " + otherProgram.getName())

    def compareSwitchTables(self, otherProgram: Program) -> None:
        currentSymbolTable = self.currentProgram.getSymbolTable()
        numMissingSwitches = 0
        numSwitchesInCurrentProg = 0

        print("Iterating through switch tables in " + self.currentProgram.getName())
        symbolIterator = currentSymbolTable.getSymbolIterator("switchdataD_*", True)

        while symbolIterator.hasNext() and not monitor.isCancelled():
            sym = symbolIterator.next()
            address = sym.getAddress()
            numSwitchesInCurrentProg += 1
            otherSyms = otherSymbolTable.getSymbols(address)
            if len(otherSyms) == 0:
                numMissingSwitches += 1
                print(numMissingSwitches + ": Missing switch table in " + otherProgram.getName() + " at " + str(address))

        symbolIterator = otherSymbolTable.getSymbolIterator("switchdataD_*", True)

        numMissingSwitches2 = 0
        numSwitchesInOtherProg = 0

        while symbolIterator.hasNext() and not monitor.isCancelled():
            sym = symbolIterator.next()
            address = sym.getAddress()
            numSwitchesInOtherProg += 1
            otherSyms = currentSymbolTable.getSymbols(address)
            if len(otherSyms) == 0:
                numMissingSwitches2 += 1
                print(numMissingSwitches2 + ": Missing switch table in " + self.currentProgram.getName() +
                      " at " + str(address))

        print("\n\ntaxxxx SWITCH TABLE COMPARE SUMMARY:\n")
        print("There are " + str(numSwitchesInCurrentProg) + " switch tables in " + self.currentProgram.getName() +
              " and " + str(numSwitchesInOtherProg) + " switch table in " + otherProgram.getName())
        print("There are " + str(numMissingSwitches) + " switch tables missing in " + otherProgram.getName() +
              " that are in " + self.currentProgram.getName())
        print("There are " + str(numMissingSwitches2) + " switch tables missing in " + self.currentProgram.getName() +
              " that are in " + otherProgram.getName())

    def compareNoReturns(self, otherProgram: Program) -> None:
        currentFunctionManager = self.currentProgram.getFunctionManager()
        numMissingNonReturningFuncs = 0
        numNonReturningFuncsInCurrentProg = 0

        print("Iterating through non-returning functions in " + self.currentProgram.getName())
        functionIterator = self.currentProgram.getListing().getFunctions(self.currentProgram.getMinAddress(), True)

        while functionIterator.hasNext() and not monitor.isCancelled():
            func = functionIterator.next()
            if func.hasNoReturn():
                numNonReturningFuncsInCurrentProg += 1
                address = func.getBody().getMinAddress()
                otherFunction = currentFunctionManager.getFunctionAt(address)
                if otherFunction is None or not otherFunction.hasNoReturn():
                    numMissingNonReturningFuncs += 1
                    print(numMissingNonReturningFuncs + ": Missing function or function is not marked as non-returning in " +
                          otherProgram.getName() + " at " + str(address))

        functionIterator = otherProgram.getListing().getFunctions(otherProgram.getMinAddress(), True)

        numMissingNonReturningFuncs2 = 0
        numNonReturningFuncsInOtherProg = 0

        while functionIterator.hasNext() and not monitor.isCancelled():
            func = functionIterator.next()
            if func.hasNoReturn():
                numNonReturningFuncsInOtherProg += 1
                address = func.getBody().getMinAddress()
                otherFunction = currentFunctionManager.getFunctionAt(address)
                if otherFunction is None or not otherFunction.hasNoReturn():
                    numMissingNonReturningFuncs2 += 1
                    print(numMissingNonReturningFuncs2 + ": Missing function or function is not marked as non-returning in " +
                          self.currentProgram.getName() + " at " + str(address))

        print("\n\ntaxxxx NON-RETURNING FUNCTION COMPARE SUMMARY:\n")
        print("There are " + str(numNonReturningFuncsInCurrentProg) + " non-returning functions in " + self.currentProgram.getName() +
              " and " + str(numNonReturningFuncsInOtherProg) + " non-returning functions in " + otherProgram.getName())
        print("There are " + str(numMissingNonReturningFuncs) + " non-returning functions missing in " + otherProgram.getName() +
              " that are in " + self.currentProgram.getName())
        print("There are " + str(numMissingNonReturningFuncs2) + " non-returning functions missing in " + self.currentProgram.getName() +
              " that are in " + otherProgram.getName())

    def compareErrors(self, otherProgram: Program) -> None:
        currentBookmarkManager = self.currentProgram.getBookmarkManager()
        numMissingErrors = 0
        numErrorsInCurrentProg = 0

        print("Iterating through errors in " + self.currentProgram.getName())
        errorIterator = currentBookmarkManager.getBookmarksIterator("Error")

        while errorIterator.hasNext() and not monitor.isCancelled():
            error = errorIterator.next()
            numErrorsInCurrentProg += 1
            address = error.getAddress()
            otherErrors = otherBookmarkManager.getBookmarks(address, "Error")
            if len(otherErrors) == 0:
                numMissingErrors += 1
                print(numMissingErrors + ": No error in " + otherProgram.getName() + " at " + str(address))

        errorIterator = otherBookmarkManager.getBookmarksIterator("Error")

        numMissingErrors2 = 0
        numErrorsInOtherProg = 0

        while errorIterator.hasNext() and not monitor.isCancelled():
            error = errorIterator.next()
            numErrorsInOtherProg += 1
            address = error.getAddress()
            otherErrors = currentBookmarkManager.getBookmarks(address, "Error")
            if len(otherErrors) == 0:
                numMissingErrors2 += 1
                print(numMissingErrors2 + ": No error in " + self.currentProgram.getName() +
                      " at " + str(address))

        print("\n\ntaxxxx ERROR COMPARE SUMMARY:\n")
        print("There are " + str(numErrorsInCurrentProg) + " errors in " + self.currentProgram.getName() +
              " and " + str(numErrorsInOtherProg) + " errors in " + otherProgram.getName())
        print("There are " + str(numMissingErrors) + " errors not in " + otherProgram.getName() +
              " that are in " + self.currentProgram.getName())
        print("There are " + str(numMissingErrors2) + " errors not in " + self.currentProgram.getName() +
              " that are in " + otherProgram.getName())

    def isString(self, mnemonic: str) -> bool:
        if mnemonic == "ds" or mnemonic == "unicode" or mnemonic == "p_unicode" or mnemonic == "p_string" or mnemonic == "p_string255" or mnemonic == "mbcs":
            return True
        return False

    def isSwitch(self, syms: [Symbol], name: str) -> bool:
        for sym in syms:
            if sym.getName().startswith(name):
                return True
        return False