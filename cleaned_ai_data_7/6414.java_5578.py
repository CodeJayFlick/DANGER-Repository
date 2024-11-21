import unittest
from ghidra_app_plugin_core_script import ScriptTaskListener
from ghidra_framework.application import Application
from ghidra_framework.plugintool import PluginTool
from ghidra_program.database import ProgramBuilder
from ghidra_program.model.address import Address
from ghidra_program.model.data import *
from ghidra_program.model.listing import Instruction, Program

class TestScript(unittest.TestCase):

    def setUp(self):
        self.env = None
        self.tool = None
        self.program = None
        self.script = None

    def testSingleString(self):
        addr = Address("01001021")
        assertData(addr, 5, "74 65 73 74 00", "ds")

        go_to(tool, program, addr)
        script_id = env.run_script(script)

        give_user_input_bytes("70 61 73 73")

        wait_for_script(script_id)

        assert_data(addr, 5, "70 61 73 73 00", "ds")

    def testLetterInString(self):
        addr = Address("010010c5")
        assertData(addr, 5, "62 69 74 65 00", "ds")

        go_to(tool, program, addr.add(1))
        script_id = env.run_script(script)

        give_user_input_bytes("79")

        wait_for_script(script_id)

        assert_data(addr, 5, "62 79 74 65 00", "ds")

    def testIncreaseStringLength(self):
        ds_addr = Address("010010ed")
        assertData(ds_addr, 6, "68 65 6c 6c 6f 00", "ds")

        go_to(tool, program, ds_addr)
        script_id = env.run_script(script)

        give_user_input_bytes("66 72 69 6e 64")

        wait_for_script(script_id)

        assert_data(ds_addr, 7, "66 72 69 6e 64 00", "ds")

    def testStringFollowedByUndefined(self):
        ds_addr = Address("010010f5")
        assertData(ds_addr, 4, "6f 6e 65 00", "ds")

        undefined_addr = ds_addr.add(4)
        assertUndefined(undefined_addr, undefined_addr. add(1), 2, "11 00")

        go_to(tool, program, ds_addr)
        script_id = env.run_script(script)

        give_user_input_bytes("6d 6f 72 65")

        wait_for_script(script_id)

        assert_data(ds_addr, 6, "6d 6f 72 65 11 00", "ds")

    def testSingleCUInst(self):
        addr = Address("0100100e")
        assertInstruction(addr, 2, "75 11", "JNZ")

        go_to(tool, program, addr)
        script_id = env.run_script(script)

        give_user_input_bytes("6a 00")

        wait_for_script(script_id)

        assert_instruction(addr, 2, "6a 00", "PUSH")

    def testIncreaseInstLength(self):
        inst_addr = Address("01001010")
        assertInstruction(inst_addr, 1, "5e", "POP")

        undefined_addr = inst_addr.add(1)
        assertUndefined(undefined_addr, undefined_addr. add(1), 1, "00")

        go_to(tool, program, inst_addr)
        script_id = env.run_script(script)

        give_user_input_bytes("ff d3")

        wait_for_script(script_id)

        assert_instruction(inst_addr, 2, "ff d3", "CALL")

    def testInstFollowedByInst(self):
        inst1_addr = Address("01001012")
        assertInstruction(inst1_addr, 2, "33 f6", "XOR")

        inst2_addr = inst1_addr.add(2)
        assertInstruction(inst2_addr, 2, "3b c6", "CMP")

        go_to(tool, program, inst1_addr)
        script_id = env.run_script(script)

        give_user_input_bytes("f6 c1 20")

        wait_for_script(script_id)

        assert_instruction(inst1_addr, 3, "f6 c1 20", "TEST")

    def testInstFollowedByData(self):
        db_addr = Address("01001070")
        assertData(db_addr, 1, "07", "db")

        undefined_addr = db_addr.add(1)
        assertUndefined(undefined_addr, undefined_addr. add(1), 2, "89 45 fc")

        go_to(tool, program, db_addr)
        script_id = env.run_script(script)

        give_user_input_bytes("8c 05 19 fd 89 35 58")

        wait_for_script(script_id)

    def testEndOfMemoryBlock(self):
        addr = Address("010085ff")
        assertUndefined(addr, addr, 1, "00")

        go_to(tool, program, addr)
        script_id = env.run_script(script)

        give_user_input_bytes("11 22")

        wait_for_swing()

    def testBytesInStructure(self):
        addr = Address("010010ac")
        assertData(addr, 4, "05 08 13 21", "fibonacci")

        go_to(tool, program, addr.add(1))
        script_id = env.run_script(script)

        give_user_input_bytes("00 01 01")

        wait_for_script(script_id)

    def testSingleCUInst(self):
        pass

if __name__ == "__main__":
    unittest.main()
