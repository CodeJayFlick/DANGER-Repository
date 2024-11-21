import unittest
from ghidra_app.util import byte_copier as ByteCopier
from ghidra_framework.model import domain_object as DomainObject
from ghidra_program.database import program_builder as ProgramBuilder
from ghidra_program.model.address import address_set_view as AddressSetView

class TestByteViewerClipboardProvider(unittest.TestCase):

    def setUp(self):
        self.program = create_program()
        self.clipboard_provider = ByteViewerClipboardProvider(None, DummyTool())

    @staticmethod
    def create_program():
        builder = ProgramBuilder("default", "TOY", None)
        builder.create_memory("test", "0x01001050", 20000)

        bytes_1 = b"0e 5e f4 77 33 58 f4 77 91 45 f4 77 88 7c f4 77 8d 70 f5 77 05 62 f4 77 f0 a3 " + \
                  b"f4 77 09 56 f4 77 10 17 f4 77 f7 29 f6 77 02 59 f4 77"
        bytes_2 = b"00 00 00 00 00 00 00 00 00 00 00 00 00"

        builder.set_bytes("0x01001050", bytes_1)
        builder.set_bytes("0x01002050", bytes_2)

        dt = DomainObject()
        p = Parameter(dt, None)
        builder.create_empty_function("ghidra", "0x01002cf5", 1, dt, p)
        builder.create_empty_function("sscanf", "0x0100415a", 1, dt, p)

        bytes_3 = b"ff 15 08 10 00 01"
        builder.disassemble("0x0100418c", len(bytes_3))
        return ProgramBuilder.get_program(builder)

    def test_copy_paste_special_byte_string(self):
        length = 4
        self.clipboard_provider.set_selection(selection("0x01001050", length))
        type_ = ByteCopier.BYTE_STRING_TYPE
        transferable = self.clipboard_provider.copy_special(type_, None)
        self.assertIsInstance(transferable, ByteStringTransferable)

        byte_string = str(transferable.get_transfer_data(DataFlavor.string_flavor))
        self.assertEqual("0e 5e f4 77", byte_string)

        paste_address = "0x01002050"
        paste(paste_address, transferable)
        assert_bytes_at(paste_address, "0e 5e f4 77", length)

    def test_copy_paste_special_byte_string_no_spaces(self):
        length = 4
        self.clipboard_provider.set_selection(selection("0x01001050", length))
        type_ = ByteCopier.BYTE_STRING_NO_SPACE_TYPE
        transferable = self.clipboard_provider.copy_special(type_, None)
        self.assertIsInstance(transferable, ByteStringTransferable)

        byte_string = str(transferable.get_transfer_data(DataFlavor.string_flavor))
        self.assertEqual("0e5ef477", byte_string)

        paste_address = "0x01002050"
        paste(paste_address, transferable)
        assert_bytes_at(paste_address, "0e 5e f4 77", length)

    def test_copy_paste_special_python_byte_string(self):
        length = 4
        self.clipboard_provider.set_selection(selection("0x01001050", length))
        type_ = ByteCopier.PYTHON_BYTE_STRING_TYPE
        transferable = self.clipboard_provider.copy_special(type_, None)
        self.assertIsInstance(transferable, ProgrammingByteStringTransferable)

        byte_string = str(transferable.get_transfer_data(DataFlavor.string_flavor))
        self.assertEqual("b'\\x0e\\x5e\\xf4\\x77'", byte_string)

        paste_address = "0x01002050"
        paste(paste_address, transferable)
        assert_bytes_at(paste_address, "0e 5e f4 77", length)

    def test_copy_paste_special_python_list_string(self):
        length = 4
        self.clipboard_provider.set_selection(selection("0x01001050", length))
        type_ = ByteCopier.PYTHON_LIST_TYPE
        transferable = self.clipboard_provider.copy_special(type_, None)
        self.assertIsInstance(transferable, ProgrammingByteStringTransferable)

        byte_string = str(transferable.get_transfer_data(DataFlavor.string_flavor))
        self.assertEqual("[ 0x0e, 0x5e, 0xf4, 0x77 ]", byte_string)

        paste_address = "0x01002050"
        paste(paste_address, transferable)
        assert_bytes_at(paste_address, "0e 5e f4 77", length)

    def test_copy_paste_special_cpp_byte_array(self):
        length = 4
        self.clipboard_provider.set_selection(selection("0x01001050", length))
        type_ = ByteCopier.CPP_BYTE_ARRAY_TYPE
        transferable = self.clipboard_provider.copy_special(type_, None)
        self.assertIsInstance(transferable, ProgrammingByteStringTransferable)

        byte_string = str(transferable.get_transfer_data(DataFlavor.string_flavor))
        self.assertEqual("{ 0x0e, 0x5e, 0xf4, 0x77 }", byte_string)

        paste_address = "0x01002050"
        paste(paste_address, transferable)
        assert_bytes_at(paste_address, "0e 5e f4 77", length)

    def test_paste(self):
        address = "0x01002050"
        transferable = self.clipboard_provider.copy_special(ByteCopier.BYTE_STRING_TYPE, None)
        paste(address, transferable)

    @staticmethod
    def selection(address_string, n):
        address = ProgramBuilder.get_program().get_address_factory().get_address(address_string)
        addresses = AddressSetView(address, address.add(n - 1))
        return ProgramSelection(addresses)

    @staticmethod
    def addr(addr):
        return ProgramBuilder.get_program().get_address_factory().get_address(addr)

    @staticmethod
    def location(address_string):
        return ProgramLocation(ProgramBuilder.get_program(), TestByteViewerClipboardProvider.addr(address_string))

    @staticmethod
    def paste(address, transferable):
        program = ProgramBuilder.get_program()
        do_paste(program, lambda: clipboard_provider.paste(transferable), False)

    @staticmethod
    def assert_bytes_at(address, bytes, length):
        memory = ProgramBuilder.get_program().get_memory()
        memory_bytes = bytearray(length)
        memory.get_bytes(addr(address), memory_bytes, 0, length)

        byte_string = NumericUtilities.convert_bytes_to_string(memory_bytes, " ")
        self.assertEqual(bytes, byte_string)


if __name__ == "__main__":
    unittest.main()

class DummyTool:
    def execute(self, command, obj):
        return command.apply_to(obj)
