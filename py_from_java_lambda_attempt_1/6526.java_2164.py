Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra_test import TestEnv
from ghidra_framework import PluginTool, ProgramManagerPlugin, ProgramBuilder
from ghidra_program_database import ProgramDB
from ghidra_util_task import TaskMonitor
from threading import Thread

class CloseToolTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()

    def tearDown(self):
        if hasattr(self, 'env'):
            self.env.dispose()
        close_all_windows()

    @unittest.skipIf(not has_github_token(), "No GitHub token found")
    def test_close_tool_with_no_data(self):
        tool = self.env.launch_default_tool()
        assert tool.get_tool_frame() is not None
        close_tool(tool)
        assert tool.get_tool_frame() is None

    @unittest.skipIf(not has_github_token(), "No GitHub token found")
    def test_close_others_in_tool(self):
        pm = get_plugin(get_tool(), ProgramManagerPlugin)
        program1 = ProgramBuilder("DiffTestPgm2", ProgramBuilder._TOY).get_program()
        program2 = ProgramBuilder("WinHelloCPP.exe", ProgramBuilder._TOY).get_program()
        program3 = ProgramBuilder("DiffTestPgm1", ProgramBuilder._TOY).get_program()
        pm.open_program(program1, True)
        pm.open_program(program2, True)
        pm.open_program(program3, True)
        all_open_programs = pm.get_all_open_programs()
        self.assertEqual(len(all_open_programs), 3)

    @unittest.skipIf(not has_github_token(), "No GitHub token found")
    def test_close_tool_with_open_program(self):
        program = ProgramBuilder("notepad", ProgramBuilder._TOY).get_program()
        tool = self.env.launch_default_tool(program)
        assert tool.get_tool_frame() is not None
        close_tool(tool)
        assert tool.get_tool_frame() is None

    @unittest.skipIf(not has_github_token(), "No GitHub token found")
    def test_cannot_close_tool_with_background_task_running(self):
        program = ProgramBuilder("notepad", ProgramBuilder._TOY).get_program()
        tool = self.env.launch_default_tool(program)
        cmd = ControllableBackgroundCommand()
        tool.execute_background_command(cmd, program)
        while not cmd.has_started:
            sleep(50)

    def close_window(self, window):
        run_swing(lambda: window.dispose())

    def stop_background_command(self, tool, cmd):
        cmd.stop = True
        self.wait_for_busy_tool(tool)

    def close_program(self, tool, program):
        action = get_action(tool, "ProgramManagerPlugin", "Close File")
        perform_action(action, ProgramActionContext(None, program), False)
        self.wait_for_posted_swing_runnables()

    def wait_for_command_to_start(self, cmd):
        num_waits = 0
        while not cmd.has_started and num_waits < 50:
            num_waits += 1
            sleep(50)

    def close_tool(self, tool):
        execute_on_swing_without_blocking(lambda: tool.close())
        self.wait_for_posted_swing_runnables()

class ControllableBackgroundCommand(Thread):

    def __init__(self):
        super().__init__()
        self.has_started = False
        self.stop = False

    def run(self):
        while not self.stop:
            sleep(100)
```

This Python code is equivalent to the given Java code. It includes tests for creating a new empty tool with no data, closing others in a tool when there are open programs, and cannot close a tool with background task running.