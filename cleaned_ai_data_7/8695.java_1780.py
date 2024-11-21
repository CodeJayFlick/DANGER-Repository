import unittest
from ghidra_ghidra import GhidraState, ConsoleService, Application, PluginTool, TestEnv
from io import StringIO
import os

class PythonScriptTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        GhidraState.initialize(new BundleHost(), None)
        self.console = self.tool.get_service(ConsoleService)

    def tearDown(self):
        GhidraState.dispose()
        self.env.dispose()

    @unittest.skip("This test is not implemented yet")
    def test_python_script(self):

        script_path = "ghidra_scripts/python_basics.py"
        try:
            output = run_python_script(Application.get_module_file("Python", script_path))
            assert output.find("Snoopy") != -1
        except FileNotFoundError as e:
            self.fail(f"Could not find python script: {script_path}")
        except Exception as e:
            self.fail(f"Exception occurred trying to run script: {e}")

    @unittest.skip("This test is not implemented yet")
    def test_python_interpreter_gone_from_state(self):

        script_path = "ghidra_scripts/python_basics.py"
        try:
            state = GhidraState(
                env.get_tool(), 
                env.get_project(), 
                None, 
                None, 
                None, 
                None
            )
            run_python_script(Application.get_module_file("Python", script_path), state)
            assert state.environment_var(PythonScript.PYTHON_INTERPRETER) is None
        except FileNotFoundError as e:
            self.fail(f"Could not find python script: {script_path}")
        except Exception as e:
            self.fail(f"Exception occurred trying to run script: {e}")

    def run_python_script(self, script_file):
        state = GhidraState(
            env.get_tool(), 
            env.get_project(), 
            None, 
            None, 
            None, 
            None
        )
        return run_python_script(script_file, state)

    @unittest.skip("This test is not implemented yet")
    def run_python_script(self, script_file, state):
        self.console.clear_messages()
        
        writer = StringIO()
        provider = PythonScriptProvider()
        script = provider.get_script_instance(script_file, writer)
        script.set(state, None, writer)
        script.run()

        self.wait_for_swing()

        text = self.console.text(0, len(self.console.text))
        return text

if __name__ == "__main__":
    unittest.main()
