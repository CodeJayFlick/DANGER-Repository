Here is the translation of the Java code into equivalent Python:

```Python
class ImageSectionHeader:
    def __init__(self, pdb):
        if not pdb:
            raise ValueError("pdb cannot be null")
        self.pdb = pdb

    def parse(self, reader):
        if len(reader) < 40:
            raise PdbException("Not enough data for ImageSectionHeader")

        name_reader = reader[:8]
        self.name = name_reader.decode('utf-8')

        self.unionPAVS = int.from_bytes(reader[8:12], 'little')
        self.virtualAddress = int.from_bytes(reader[12:16], 'little')
        self.rawDataSize = int.from_bytes(reader[16:20], 'little')
        self.rawDataPointer = int.from_bytes(reader[20:24], 'little')
        self.relocationsPointer = int.from_bytes(reader[24:28], 'little')
        self.lineNumbersPointer = int.from_bytes(reader[28:32], 'little')
        self.numRelocations = int.from_bytes(reader[32:34], 'little', signed=True)
        self.numLineNumbers = int.from_bytes(reader[34:36], 'little', signed=True)
        self.characteristics = int.from_bytes(reader[36:], 'little')

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def unionPAVS(self):
        return self._unionPAVS

    @unionPAVS.setter
    def unionPAVS(self, value):
        self._unionPAVS = value

    @property
    def virtualAddress(self):
        return self._virtualAddress

    @virtualAddress.setter
    def virtualAddress(self, value):
        self._virtualAddress = value

    @property
    def rawDataSize(self):
        return self._rawDataSize

    @rawDataSize.setter
    def rawDataSize(self, value):
        self._rawDataSize = value

    @property
    def rawDataPointer(self):
        return self._rawDataPointer

    @rawDataPointer.setter
    def rawDataPointer(self, value):
        self._rawDataPointer = value

    @property
    def relocationsPointer(self):
        return self._relocationsPointer

    @relocationsPointer.setter
    def relocationsPointer(self, value):
        self._relocationsPointer = value

    @property
    def lineNumbersPointer(self):
        return self._lineNumbersPointer

    @lineNumbersPointer.setter
    def lineNumbersPointer(self, value):
        self._lineNumbersPointer = value

    @property
    def numRelocations(self):
        return self._numRelocations

    @numRelocations.setter
    def numRelocations(self, value):
        self._numRelocations = value

    @property
    def numLineNumbers(self):
        return self._numLineNumbers

    @numLineNumbers.setter
    def numLineNumbers(self, value):
        self._numLineNumbers = value

    @property
    def characteristics(self):
        return self._characteristics

    @characteristics.setter
    def characteristics(self, value):
        self._characteristics = value

    def dump(self, writer, section_num):
        writer.write("ImageSectionHeader------------------------------------------\n")
        writer.write(f"Section Number: {section_num}\n")
        writer.write(f"name: {self.name}\n")

        # TODO: See the to-do above regarding unionPAVS.
        writer.write(f"unionPAVS: 0x{self.unionPAVS:x}\n")
        writer.write(f"virtualAddress: 0x{self.virtualAddress:x}\n")
        writer.write(f"rawDataSize: 0x{self.rawDataSize:x}\n")
        writer.write(f"rawDataPointer: 0x{self.rawDataPointer:x}\n")
        writer.write(f"relocationsPointer: 0x{self.relocationsPointer:x}\n")
        writer.write(f"lineNumbersPointer: 0x{self.lineNumbersPointer:x}\n")
        writer.write(f"numRelocations: {self.numRelocations}\n")
        writer.write(f"numLineNumbers: {self.numLineNumbers}\n")
        writer.write(f"characteristics: 0x{self.characteristics:x}\n")

        writer.write("End ImageSectionHeader--------------------------------------\n")


class PdbException(Exception):
    pass
```

Please note that Python does not have direct equivalent of Java's `abstract` keyword. In this translation, I've removed the abstract class declaration and directly implemented the methods in the `ImageSectionHeader` class.

Also, Python does not support unsigned integers like Java's `unsigned 32-bit`. Instead, you can use Python's built-in integer type which is signed by default.