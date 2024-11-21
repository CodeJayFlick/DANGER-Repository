Here is the translation of the given Java code into Python:

```Python
import re
from ghidra_app_plugin import GhidraAppPlugin
from ghidra.program.model.address import Address
from ghidra.program.model.data import Pointer32DataType
from ghidra.app.plugin.core.searchmem import MemSearchRegExTest

class TestMemSearchRegEx(MemSearchRegExTest):
    def setUp(self):
        super().setUp()
        self.selectRadioButton("Regular Expression")

    def buildProgram(self) -> Program:
        builder = ProgramBuilder("TestX86", _X86)
        builder.createMemory(".text", "0x1001000", 0x6600)
        builder.createMemory(".data", "0x1008000", 0x600)
        builder.createMemory(".rsrc", "0x100A000", 0x5400)
        builder.createMemory(".bound_Import_table", "0xF0000248", 0xA8)

        # create and disassemble a function
        bytes = [
            "55 8b ec 83 7d 14 00 56 8b 35 e0 10 00 01 57 74 09 ff 75 14 ff d6 8b f8 eb 02",
            "33 ff ff 75 10 ff d6 03 c7 8d 44 00 02 50 6a 40 ff 15 dc 10 00 01 8b f0 85 f6",
            "74 27 56 ff 75 14 ff 75 10 e8 5c ff ff ff ff 75 18 ff 75 0c 56 ff 75 08 ff 15",
            "04 12 00 01 56 8b f8 ff 15 c0 10 00 01 eb 14 ff 75 18 ff 75 0c ff 75 10 ff 75",
            "08 ff 15 04 12 00 01 8b f8 8b c7 5f 5e 5d c2 14"
        ]
        builder.setBytes("0x01002cf5", "".join(bytes))
        builder.disassemble("0x01002cf5", 0x121, True)
        builder.createFunction("0x01002cf5")

        # create and disassemble some code not in a function
        bytes = [
            "ff 15 c4 10 00 01 8b d8 33 f6 3b de 74 06"
        ]
        builder.setBytes("0x10029bd", "".join(bytes))
        builder.disassemble("0x10029bd", 0xe, True)

        bytes = [
            "f3 a5 99 b9 30 fd ff ff ff 75 08 f7 f9"
        ]
        builder.setBytes("0x10035f5", "".join(bytes))
        builder.disassemble("0x10035f5", 0xd, True)

        bytes = [
            "8b 0d 58 80 00 01"
        ]
        builder.setBytes("0x10040d9", "".join(bytes))
        builder.disassemble("0x10040d9", 0x6, True)

        bytes = [
            "6a 01",
            "6a 01"
        ]
        builder.setBytes("0x010029cb", "".join(bytes))
        builder.setBytes("0x010029cd", "".join(bytes))
        builder.disassemble("0x010029cb", 0x4, True)

        bytes = [
            "6a 01"
        ]
        builder.setBytes("0x01002826", "".join(bytes))
        builder.disassemble("0x01002826", 0x2, True)

        # create some data
        bytes = [
            "85 4f dc 77",
            "e3 b3 f4 77",
            "3d b6 f4 77"
        ]
        for i in range(1):
            builder.applyDataType("0x1001004", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+4)}", "".join(bytes))

        bytes = [
            "e3 b3 f4 77",
            "50 ff 75 08 e8 8d 3c 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "50 ff 75 08"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "65 00 6e 00 64 00 69 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "4e 00 65 00 77 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "55 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "64 00 00 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "50 ff 75 08 e8 8d 3c 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "50 ff 75 08"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "65 00 6e 00 64 00 69 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "4e 00 65 00 77 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "55 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "64 00 00 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "50 ff 75 08 e8 8d 3c 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "50 ff 75 08"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "65 00 6e 00 64 00 69 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "4e 00 65 00 77 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "55 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "64 00 00 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "50 ff 75 08 e8 8d 3c 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "50 ff 75 08"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "65 00 6e 00 64 00 69 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "4e 00 65 00 77 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "55 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "64 00 00 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "50 ff 75 08 e8 8d 3c 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "50 ff 75 08"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "65 00 6e 00 64 00 69 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "4e 00 65 00 77 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder.setBytes(f"0x{hex(i*8+408)}", "".join(bytes))

        bytes = [
            "55 00"
        ]
        for i in range(2):
            builder.applyDataType(f"0x{hex(i*8+400)}", Pointer32DataType(), 1)
            builder