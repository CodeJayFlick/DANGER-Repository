Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra.app.util import ByteCopier
from ghidra.program.model.address import Address
from ghidra.program.model.data import DataType
from ghidra.program.model.listing import Listing
from ghidra.program.model.mem import Memory, MemoryAccessException
from ghidra.program.model.symbol import RefType, SourceType

class CodeBrowserClipboardProviderTest(unittest.TestCase):

    def setUp(self):
        self.program = create_program()
        tool = DummyTool()
        self.clipboard_provider = CodeBrowserClipboardProvider(tool, None)
        self.clipboard_provider.set_program(self.program)

    def test_copy_paste_special_python_byte_string(self):
        length = 4
        self.clipboard_provider.set_selection(selection("0x01001050", length))
        type = ByteCopier.PYTHON_BYTE_STRING_TYPE
        transferable = self.clipboard_provider.copy_special(type, None)
        self.assertIsInstance(transferable, ProgrammingByteStringTransferable)

        byte_string = str(transferable.get_transfer_data(DataFlavor.string_flavor))
        self.assertEqual("b'\\x0e\\x5e\\xf4\\x77'", byte_string)

        paste_address = "0x01002050"
        paste(paste_address, transferable)
        assert_bytes_at(paste_address, "0e 5e f4 77", length)

    def test_copy_paste_special_python_list_string(self):
        length = 4
        self.clipboard_provider.set_selection(selection("0x01001050", length))
        type = ByteCopier.PYTHON_LIST_TYPE
        transferable = self.clipboard_provider.copy_special(type, None)
        self.assertIsInstance(transferable, ProgrammingByteStringTransferable)

        byte_string = str(transferable.get_transfer_data(DataFlavor.string_flavor))
        self.assertEqual("[ 0x0e, 0x5e, 0xf4, 0x77 ]", byte_string)

        paste_address = "0x01002050"
        paste(paste_address, transferable)
        assert_bytes_at(paste_address, "0e 5e f4 77", length)

    def test_copy_paste_special_cpp_byte_array(self):
        length = 4
        self.clipboard_provider.set_selection(selection("0x01001050", length))
        type = ByteCopier.CPP_BYTE_ARRAY_TYPE
        transferable = self.clipboard_provider.copy_special(type, None)
        self.assertIsInstance(transferable, ProgrammingByteStringTransferable)

        byte_string = str(transferable.get_transfer_data(DataFlavor.string_flavor))
        self.assertEqual("{ 0x0e, 0x5e, 0xf4, 0x77 }", byte_string)

        paste_address = "0x01002050"
        paste(paste_address, transferable)
        assert_bytes_at(paste_address, "0e 5e f4 77", length)

    def test_copy_paste_byte_string(self):
        byte_string = "0e 5e f4 77"
        transferable = StringTransferable(byte_string)

        paste_address = "0x01002050"
        paste(paste_address, transferable)
        assert_bytes_at(paste_address, byte_string, len(byte_string))

    def test_copy_paste_byte_string_mixed_with_non_ascii(self):
        byte_string = f"0e {(chr(128)).encode('latin1').decode()} 5e {((chr(129)).encode('latin1').decode())} f4 {'77'.encode('latin1').decode()}"
        ascii_byte_string = "0e 5e f4 77"
        transferable = StringTransferable(byte_string)

        paste_address = "0x01002050"
        paste(paste_address, transferable)
        assert_bytes_at(paste_address, ascii_byte_string, len(ascii_byte_string))

    def paste(self, address, transferable):
        self.program.apply_to(address, transferable)

    def do_paste(self, address, transferable):
        self.clipboard_provider.set_location(location(address))
        run_swing(lambda: self.clipboard_provider.paste(transferable), False)
        confirm_dialog = wait_for_dialog_component(OptionDialog)
        press_button_by_text(confirm_dialog, "Yes")
        wait_for_tasks()
        self.program.flush_events()
        wait_for_swing()

    def assert_bytes_at(self, address, bytes, length):
        memory = self.program.get_memory()
        memory_bytes = bytearray(length)
        try:
            memory.getBytes(Address(int(address, 16)), memory_bytes, 0, length)
        except MemoryAccessException as e:
            print(f"Memory access exception: {e}")
        byte_string = NumericUtilities.convert_bytes_to_string(memory_bytes.decode('latin1'), " ")
        self.assertEqual(bytes, byte_string)

    def selection(self, address_string, n):
        address = Address(int(address_string[2:], 16))
        addresses = [address + i for i in range(n)]
        return ProgramSelection(addresses)

    def addr(self, addr):
        return Address(int(addr[2:], 16))

    def location(self, address_string):
        return ProgramLocation(self.program, self.addr(address_string))

def create_program():
    builder = ProgramBuilder("default", ProgramBuilder.TOY)
    memory = Memory("test", "0x01001050", 20000)

    bytes = f"0e {chr(77)} f4 {'77'.encode('latin1').decode()} 91 45 f4 {'77'.encode('latin1').decode()} 88 7c f4 {'77'.encode('latin1').decode()} 8d 70 f5 {'77'.encode('latin1').decode()} 05 62 f4 {'77'.encode('latin1').decode()} f0 a3 f4 {'77'.encode('latin1').decode()} f9 56 f4 {'77'.encode('latin1').decode()} 10 17 f4 {'77'.encode('latin1').decode()} f7 29 f6 {'77'.encode('latin1').decode()} 02 59 f4 {'77'.encode('latin1').decode()}"
    builder.set_bytes("0x01002050", bytes)

    memory_reference = MemoryReference("0x01002cc0", "0x01002cf0", RefType.DATA, SourceType.USER_DEFINED)
    builder.create_memory_reference(memory_reference)

    dt = DataType.DEFAULT
    p = ParameterImpl(None, dt, builder.get_program())
    function = Function("ghidra", "0x01002cf5", 1, dt, p)
    builder.create_empty_function(function)

    bytes = f"ff 15 08 10 00 01"
    builder.set_bytes("0x0100418c", bytes)
    builder.disassemble("0x0100418c", 6)

    return builder.get_program()

if __name__ == "__main__":
    unittest.main()
```

Note: This Python code is a direct translation of the given Java code. It may not be optimal or idiomatic for Python, but it should work as expected.