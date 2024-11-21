Here is the translation of the given Java code into Python:

```Python
import ghidra.app.script.GhidraScript;
from ghidra.program.model.address import AddressSet;
from ghidra.program.model.data.AlignmentDataType;

class CondenseFillerBytes(GhidraScript):
    def __init__(self):
        self.listing = None;
        self.memory = None;

    @Override
    public void run(self) throws Exception:
        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();

        filler = null;

        possibleAddrSet = AddressSet();

        # Ask for min run length
        minBytes = askInt("CondenseFillerBytes", "Enter minimum number of sequential bytes to collapse");

        prgmFillerBytes = bytearray(minBytes);  # filler bytes found in program

        # Ask for a fill value.   "Auto" wants the program to try and figure out the value.
        fillValue = askString("CondenseFillerBytes - Enter Fill Value", "Enter fill byte to search for and collapse (Examples: 0, 00, 90, cc). \"Auto\" will make the program determine the value (by greatest count). ", "Auto");

        # Check response
        if fillValue.lower() == "auto":
            filler = "0x" + determineFillerValue();
        else:
            filler = "0x" + str(fillValue);

        print("filler byte chosen: " + filler);

        targetFillerBytes = bytearray(minBytes);
        fillerByte = int(filler, 16).bytevalue()
        for i in range(len(targetFillerBytes)):
            targetFillerBytes[i] = fillerByte

        funcIter = listing.getFunctions(True)
        while funcIter.hasNext() and not monitor.isCancelled():
            # Get undefined byte immediately following function
            fillerAddr = funcIter.next().getBody().getMaxAddress().next()
            undefData = listing.getUndefinedDataAt(fillerAddr);
            if undefData is None:
                continue;

            memory.getBytes(fillerAddr, prgmFillerBytes)
            if bytes(prgmFillerBytes) == targetFillerBytes:

                # Determine actual length of filler bytes
                fillerLen = 1;
                undefDataStringRep = undefData.getDefaultValueRepresentation();
                addrIter = possibleAddrSet.getAddresses(fillerAddr.next(), True);
                while addrIter.hasNext():
                    nextAddr = addrIter.next()
                    if listing.isUndefined(nextAddr, nextAddr):
                        break;
                    else:
                        fillerLen += 1;

                # Check if immediate data after filler bytes is undefined
                if listing.isUndefined(fillerAddr.add(fillerLen), fillerAddr.add(fillerLen)):
                    possibleAddrSet.add(fillerAddr);
                    print("*** Possible Alignment datatype at " + str(fillerAddr));
                    continue;
                else:
                    listing.createData(fillerAddr, AlignmentDataType(), fillerLen)
                    print("Applied Alignment datatype at " + str(fillerAddr));

        if not possibleAddrSet.isEmpty():
            popup("Script complete.\n\nSome additional possible filler bytes where the Alignment datatype could be applied were found.\nPress OK to see a table of these addresses.");
            show("Possible Addresses", possibleAddrSet);

    def determineFillerValue(self):
        funcIter = listing.getFunctions(True)
        fillValuesHash = {}
        while funcIter.hasNext() and not monitor.isCancelled():
            maxAddress = funcIter.next().getBody().getMaxAddress()
            undefData = listing.getUndefinedDataAt(maxAddress.next())
            if undefData is None:
                continue;
            key = ProgramUtilities.getByteCodeString(undefData)
            if fillValuesHash.has_key(key):
                val = int(fillValuesHash[key])
                fillValuesHash[key] = str(val + 1);
            else:
                fillValuesHash[key] = "1";

        print("Possible filler values (and their counts): " + str(fillValuesHash));

        # Decide that filler value is the one with the greatest count
        return getValueWithHighestCount(fillValuesHash);

    def getValueWithHighestCount(self, fillValuesHash):
        valIterator = iter(fillValuesHash.values())
        max = int(next(valIterator))
        while True:
            nextVal = int(next(valIterator));
            if nextVal > max:
                max = nextVal;
            else:
                break;

        # Determine key corresponding to max val
        for key in fillValuesHash.keys():
            if str(fillValuesHash[key]) == str(max):
                return "0x" + key

        # Should theoretically never reach here
        return None;
```

Please note that Python does not support the exact equivalent of Java's `@Override` annotation.