Here is the translation of the Java code into Python:

```Python
class ListingDiff:
    def __init__(self):
        self.correlation = None
        self.unmatchedCode1 = set()
        self.unmatchedCode2 = set()
        self.byteDiffs1 = set()
        self.byteDiffs2 = set()
        self.codeUnitDiffs1 = set()
        self.codeUnitDiffs2 = set()

    def setCorrelation(self, correlation):
        if correlation is None:
            self.init()
            return
        self.correlation = correlation
        self.getDiffs()

    def hasCorrelation(self):
        return self.correlation is not None

    def init(self):
        self.unmatchedCode1 = set()
        self.unmatchedCode2 = set()
        self.codeUnitDiffs1 = set()
        self.codeUnitDiffs2 = set()
        self.byteDiffs1 = set()
        self.byteDiffs2 = set()

    def getDiffs(self):
        if not hasattr(self, 'correlation'):
            return
        addrSet1 = self.correlation.getAddressesInFirst()
        addrSet2 = self.correlation.getAddressesInSecond()
        listing1 = self.correlation.getFirstProgram().getListing()
        listing2 = self.correlation.getSecondProgram().getListing()

        cuIter1 = listing1.getCodeUnits(addrSet1, True)
        cuIter2 = listing2.getCodeUnits(addrSet2, True)

        for cu in cuIter1:
            minAddr = cu.getMinAddress()
            addr2 = self.correlation.getAddressInSecond(minAddr)
            if addr2 is None:
                self.unmatchedCode1.addRange(cu.getMinAddress(), cu.getMaxAddress())
                continue
            codeUnit2 = listing2.getCodeUnitAt(addr2)

            self.getByteDiffs(cu, codeUnit2, self.byteDiffs1)

            self.getCodeUnitDiffs(cu, codeUnit2, self.codeUnitDiffs1)
        for cu in cuIter2:
            minAddr = cu.getMinAddress()
            addr1 = self.correlation.getAddressInFirst(minAddr)
            if addr1 is None:
                self.unmatchedCode2.addRange(cu.getMinAddress(), cu.getMaxAddress())
                continue
            codeUnit1 = listing1.getCodeUnitAt(addr1)

            self.getByteDiffs(codeUnit1, cu, self.byteDiffs2)

            self.getCodeUnitDiffs(codeUnit1, cu, self.codeUnitDiffs2)
        self.notifyListeners()

    def recomputeCodeUnitDiffs(self):
        if not hasattr(self, 'correlation'):
            return
        addrSet1 = self.correlation.getAddressesInFirst()
        addrSet2 = self.correlation.getAddressesInSecond()
        listing1 = self.correlation.getFirstProgram().getListing()
        listing2 = self.correlation.getSecondProgram().getListing()

        cuIter1 = listing1.getCodeUnits(addrSet1, True)
        cuIter2 = listing2.getCodeUnits(addrSet2, True)

        for cu in cuIter1:
            minAddr = cu.getMinAddress()
            addr2 = self.correlation.getAddressInSecond(minAddr)
            if addr2 is None:
                continue
            codeUnit2 = listing2.getCodeUnitAt(addr2)

            self.getCodeUnitDiffs(cu, codeUnit2, self.codeUnitDiffs1)
        for cu in cuIter2:
            minAddr = cu.getMinAddress()
            addr1 = self.correlation.getAddressInFirst(minAddr)
            if addr1 is None:
                continue
            codeUnit1 = listing1.getCodeUnitAt(addr1)

            self.getCodeUnitDiffs(codeUnit1, cu, self.codeUnitDiffs2)
        self.notifyListeners()

    def getByteDiffs(self, codeUnit1, codeUnit2, byteDiffs):
        if codeUnit2 is None:
            byteDiffs.addRange(codeUnit1.getMinAddress(), codeUnit1.getMaxAddress())
        else:
            bytes1 = codeUnit1.getBytes()
            bytes2 = codeUnit2.getBytes()

            minBytes = min(len(bytes1), len(bytes2))
            for i in range(minBytes):
                if bytes1[i] != bytes2[i]:
                    byteDiffs.add(codeUnit1.getMinAddress().add(i))

    def getCodeUnitDiffs(self, codeUnit1, codeUnit2, cuDiffs):
        if not self.equivalentCodeUnits(codeUnit1, codeUnit2):
            cuDiffs.addRange(codeUnit1.getMinAddress(), codeUnit1.getMaxAddress())

    def equivalentCodeUnits(self, codeUnit1, codeUnit2):
        return self.isSameMnemonic(codeUnit1, codeUnit2) and \
               not self.doesEntireOperandSetDiffer(codeUnit1, codeUnit2)

    def isSameMnemonic(self, codeUnit1, codeUnit2):
        if not self.sameType(codeUnit1, codeUnit2):
            return False
        return codeUnit1.getMnemonicString() == codeUnit2.getMnemonicString()

    def sameType(self, codeUnit1, codeUnit2):
        return isinstance(codeUnit1, (Instruction, Data)) and \
               isinstance(codeUnit2, (Instruction, Data))

    def doesEntireOperandSetDiffer(self, codeUnit1, codeUnit2):
        if not self.sameType(codeUnit1, codeUnit2):
            return True
        numOperands = codeUnit1.getNumOperands()
        otherNumOperands = codeUnit2.getNumOperands()

        return numOperands != otherNumOperands

    def getListing1UnmatchedCode(self):
        return set([addr for addr in self.unmatchedCode1])

    def getListing2UnmatchedCode(self):
        return set([addr for addr in self.unmatchedCode2])

    def printFunctionComparisonDiffs(self):
        buffer = StringBuffer()
        buffer.append("Unmatched Diffs 1: " + str(self.getListing1UnmatchedCode()) + "\n")
        buffer.append("Unmatched Diffs 2: " + str(self.getListing2UnmatchedCode()) + "\n")

    def isIgnoringByteDiffs(self):
        return self.ignoreByteDiffs

    def setIgnoreByteDiffs(self, ignore):
        self.ignoreByteDiffs = ignore
        if hasattr(self, 'correlation'):
            self.recomputeCodeUnitDiffs()
        self.notifyListeners()

    def getListing1Diffs(self):
        diffs = set([addr for addr in self.getListing1ByteDiffs()])
        diffs.update(set([addr for addr in self.codeUnitDiffs1]))
        return DiffUtility.getCodeUnitSet(diffs, self.correlation.getFirstProgram())

    def getListing2Diffs(self):
        diffs = set([addr for addr in self.getListing2ByteDiffs()])
        diffs.update(set([addr for addr in self.codeUnitDiffs2]))
        return DiffUtility.getCodeUnitSet(diffs, self.correlation.getSecondProgram())
```

Please note that this is a direct translation of the Java code into Python.