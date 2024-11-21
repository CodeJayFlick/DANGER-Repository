import re

class MemSearchDecimal1Test:
    def __init__(self):
        pass

    def setUp(self):
        # Code for setting up test environment goes here.
        pass

    def build_program(self):
        program = {}
        program["text"] = {"start": 0x1001000, "end": 0x6600}
        program["data"] = {"start": 0x1008000, "end": 0x600}
        program["rsrc"] = {"start": 0x100A000, "end": 0x5400}
        program["bound_import_table"] = {"start": 0xF0000248, "end": 0xA8}
        program["debug_data"] = {"start": 0xF0001300, "end": 0x1C}

        # Create and disassemble a function
        code = bytes.fromhex(
            "5502ec837d14005635e0100577409ff75014ffd6837f8eb0233ff75f0506a40ff15dc1000018bf085f67427256ff7514ff7510e85cffff75f18ff750ce8504120001568bf8ff1504100120168bfc57f5d c214"
        )
        program["function"] = {"start": 0x01002cf5, "end": 121}

        # Create some data
        code = bytes.fromhex("854fdc77")
        program["data"][0] = {"start": 0x1001004, "code": code}
        program["encoded_strings"] = [
            {"start": 0x01001708, "value": "Notepad", "encoding": "UTF-16BE"},
            {"start": 0x01001740, "value": "something else", "encoding": "UTF-16BE"},
            {"start": 0x010013cc, "value": "notepad.exe", "encoding": "US_ASCII"}
        ]

        # Create some undefined data
        code = bytes.fromhex("4e0006650077700")
        program["data"][1] = {"start": 0x1001500, "code": code}
        code = bytes.fromhex("5500")
        program["data"][2] = {"start": 0x1003000, "code": code}
        code = bytes.fromhex("64000000640000")  # 100 dec
        program["data"][3] = {"start": 0x1004100, "code": code}
        code = bytes.fromhex("50ff7508e88d3400")  # 1.588386874245921e-307
        program["data"][4] = {"start": 0x1004200, "code": code}
        code = bytes.fromhex("50ff75087.4027124e-34 float")
        program["data"][5] = {"start": 0x1004247, "code": code}
        code = bytes.fromhex("650066006d00646900")  # 29555302058557541 qword
        program["data"][6] = {"start": 0x1004270, "code": code}

        return program

    def test_search_byte_backward(self):
        program = self.build_program()
        goto(0x01002d6d)
        select_radio_button("Byte")
        set_value_text("8")
        addrs = [Address(i) for i in range(0x1002d5b, 0x1002d3e)]
        perform_search_test(addrs, "Previous")

    def show_mem_search_dialog(self):
        super().show_mem_search_dialog()
        select_radio_button("Decimal")


class Address:
    def __init__(self, value):
        self.value = value

# Usage
test = MemSearchDecimal1Test()
test.setUp()
program = test.build_program()
test.test_search_byte_backward()
