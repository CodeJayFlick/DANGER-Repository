Here is the translation of the given Java code into Python:

```Python
import re
from ghidra import GhidraScript
from ghidra.program.model.address import AddressSetView
from ghidra.program.model.data import String

class SearchMemoryForStringsRegExScript(GhidraScript):
    def run(self):
        search_set = self.currentSelection if self.currentSelection else self.currentProgram.getMemory()

        regex_str = input("Please enter your regex: ")
        pattern = re.compile(regex_str)

        matching_address_list = []

        for range in search_set.getAddressRanges():
            print(f"Searching... {range.getMinAddress()} to {range.getMaxAddress()}")
            bytes = bytearray(range.getLength())
            self.currentProgram.getMemory().getBytes(range.getMinAddress(), bytes)
            data = str.encode('ISO-8859-1').join(map(lambda x: bytes[x], range)))

            match = pattern.search(data.decode("ISO-8859-1"))
            while match:
                start_index = match.start()
                address = range.getMinAddress() + start_index
                matching_address_list.append(address)

                if len(matching_address_list) > 500:
                    print("More than 500 matches found.")
                    return

                if address >= range.getMaxAddress():
                    break

                match = pattern.search(data.decode("ISO-8859-1"), match.end())

        if not matching_address_list:
            print("No match found")
            return
        addrs = tuple(matching_address_list)
        self.show(addrs)

```

Please note that Python's `re` module does not support the same functionality as Java's regular expression engine.