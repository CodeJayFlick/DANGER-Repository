import os
import sys
import threading
from io import StringIO

class GhidraScript:
    def __init__(self):
        self.interpreter_running = False

    def run(self):
        if hasattr(self, 'state'):
            interpreter = self.state.get_environment_var('PYTHON_INTERPRETER')
            if interpreter is not None:
                self.run_in_existing_environment(interpreter)
            else:
                self.run_in_new_environment()
        else:
            print("No state found")

    def run_script(self, script_name):
        if hasattr(self, 'state'):
            interpreter = self.state.get_environment_var('PYTHON_INTERPRETER')
            if interpreter is None:
                raise Exception("Could not get Ghidra Python interpreter!")
            resource_file = find_script_by_name(script_name)
            provider = ghidra_script_util.get_provider(resource_file)
            script_instance = provider.get_script_instance(resource_file, writer)
            if script_instance is None:
                raise ValueError(f"Script does not exist: {script_name}")
            if self.state == state:
                update_state_from_variables()
            if isinstance(script_instance, PythonScript):
                script_instance.set(self.state, monitor, writer)
                interpreter.exec_file(source_file, script_instance)
            else:
                script_instance.execute(self.state, monitor, writer)
        return

    def run_in_existing_environment(self, interpreter):
        interpreter.exec_file(source_file, self)

    def run_in_new_environment(self):
        interpreter = GhidraPythonInterpreter.get()
        stdout = get_stdout()
        stderr = get_stderr()
        interpreter.set_out(stdout)
        interpreter.set_err(stderr)
        state.add_environment_var('PYTHON_INTERPRETER', interpreter)
        execution_thread = PythonScriptExecutionThread(self, interpreter, self.interpreter_running)
        self.interpreter_running = True
        execution_thread.start()

    def sleep100millis(self):
        try:
            time.sleep(0.1)
        except Exception as e:
            pass

def get_stdout():
    if hasattr(state.get_tool(), 'get_service'):
        console = state.get_tool().get_service(ConsoleService)
        return console.get_std_out()
    else:
        return StringIO()

def get_stderr():
    if hasattr(state.get_tool(), 'get_service'):
        console = state.get_tool().get_service(ConsoleService)
        return console.get_std_err()
    else:
        return sys.stderr

class PythonScript(GhidraScript):
    def __init__(self, source_file):
        super().__init__()
        self.source_file = source_file
