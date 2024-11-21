Here is the translation of the Java code into Python:

```Python
class PythonPlugin:
    def __init__(self):
        self.console = None
        self.interpreter = GhidraPythonInterpreter()
        self.interactive_script = None
        self.interactive_task_monitor = None
        self.input_thread = None

    @property
    def console(self):
        return self._console

    @console.setter
    def console(self, value):
        self._console = value

    @property
    def interpreter(self):
        return self._interpreter

    @interpreter.setter
    def interpreter(self, value):
        self._interpreter = value

    @property
    def interactive_script(self):
        return self._interactive_script

    @interactive_script.setter
    def interactive_script(self, value):
        self._interactive_script = value

    @property
    def interactive_task_monitor(self):
        return self._interactive_task_monitor

    @interactive_task_monitor.setter
    def interactive_task_monitor(self, value):
        self._interactive_task_monitor = value

    @property
    def input_thread(self):
        return self._input_thread

    @input_thread.setter
    def input_thread(self, value):
        self._input_thread = value

    def init(self):
        self.console = InterpreterConsole()
        welcome()
        self.console.add_first_activation_callback(lambda: reset_interpreter())
        create_actions()

    def create_actions(self):
        # Interrupt Interpreter
        interrupt_action = DockingAction("Interrupt Interpreter", "Python")
        interrupt_action.set_description("Interrupt Interpreter")
        interrupt_action.set_toolbar_data(ResourceManager.load_image("images/dialog-cancel.png"), None)
        interrupt_action.set_enabled(True)
        interrupt_action.set_key_binding_data(KeyEvent.VK_I, 0x0001)
        self.console.add_action(interrupt_action)

        # Reset Interpreter
        reset_action = DockingAction("Reset Interpreter", "Python")
        reset_action.set_description("Reset Interpreter")
        reset_action.set_toolbar_data(ResourceManager.load_image("images/reload3.png"), None)
        reset_action.set_enabled(True)
        reset_action.set_key_binding_data(KeyEvent.VK_D, 0x0001)
        self.console.add_action(reset_action)

    def reset_interpreter(self):
        TaskLauncher.launch_modal("Resetting Python...", lambda: reset_interpreter_background())
        return

    def reset_interpreter_background(self):
        if not hasattr(self, 'interpreter'):
            # Setup options
            tool_options = ToolOptions()
            include_builtins = tool_options.get_boolean(INCLUDE_BUILTINS_LABEL, INCLUDE_ Builtins_DEFAULT)
            tool_options.register_option(INCLUDE_BUILTINS_LABEL, INCLUDE_BUILTINS_DEFAULT, None,
                                          INCLUDE_BUILTINS_DESCRIPTION)

        if not hasattr(self, 'interpreter'):
            self.interpreter = GhidraPythonInterpreter()
        else:
            self.input_thread.shutdown()
            self.input_thread = None
            self.interpreter.cleanup()
            self.interpreter = GhidraPythonInterpreter()

        # Reset the console.
        self.console.clear()
        self.console.set_prompt(self.interpreter.get_primary_prompt())

        # Tie the interpreter's input/output to the plugin's console.
        self.interpreter.set_in(self.console.get_stdin())
        self.interpreter.set_out(self.console.get_stdout())
        self.interpreter.set_err(self.console.get_stderr())

        welcome()

        interactive_script = PythonScript()
        interactive_task_monitor = PythonInteractiveTaskMonitor(self.console.get_stdout())

        # Start the input thread that receives python commands to execute.
        self.input_thread = PythonPluginInputThread(self)
        self.input_thread.start()

    def options_changed(self, tool_options, option_name, old_value, new_value):
        if option_name.startswith(PythonCodeCompletionFactory.COMPLETION_LABEL):
            PythonCodeCompletionFactory.change_options(tool_options, option_name, old_value, new_value)

    def get_completions(self, cmd):
        interactive_script.set_source_file(ResourceFile(File("python")))
        interactive_script.set(GhidraState(), self.interactive_task_monitor, self.console.get_out_writer())

        return self.interpreter.get_command_completions(cmd, include_builtins)

    def dispose(self):
        interrupt()
        if hasattr(self, 'input_thread'):
            self.input_thread.shutdown()

        if hasattr(self, 'console'):
            self.console.dispose()

        if hasattr(self, 'interpreter'):
            self.interpreter.cleanup()

    def interrupt(self):
        if not hasattr(self, 'interpreter'):
            return
        self.interpreter.interrupt(input_thread.get_python_plugin_execution_thread())
        self.console.set_prompt(interpreter.get_primary_prompt())

    def reset(self):
        do_an_interrupt()
        reset_interpreter()

    @property
    def title(self):
        return "Python"

    @property
    def to_string(self):
        return get_plugin_description().name

    @property
    def icon(self):
        return ResourceManager.load_image("images/python.png")

    def welcome(self):
        self.console.get_out_writer().println("Python Interpreter for Ghidra")
        self.console.get_out_writer().println(f"Based on Jython version {PySystemState.version}")
        self.console.get_out_writer().println("Press 'F1' for usage instructions")


class PythonInteractiveTaskMonitor(TaskMonitorAdapter):
    def __init__(self, print_writer):
        super().__init__()
        self.output = print_writer

    @property
    def output(self):
        return self._output

    @output.setter
    def output(self, value):
        self._output = value

    def set_message(self, message):
        self.output.println(f"<python-interactive>: {message}")
```

Note that this is a direct translation of the Java code into Python. The resulting Python code may not be idiomatic or optimal for Python programming.