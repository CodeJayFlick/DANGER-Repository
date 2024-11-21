import sys
from types import MethodType
from collections import defaultdict

class GhidraPythonInterpreter:
    def __init__(self):
        self.python_initialized = False
        self.default_python_path = []
        self.interrupt_trace_function = None
        self.introspect_module = None
        self.builtin_module = None
        self.interrupt = None
        self.script_methods_injected = False
        self.cleaned_up = False

    def get(self):
        if not self.python_initialized:
            try:
                # Setup python home directory
                PythonUtils.setup_python_home_dir()
                
                # Setup python cache directory
                PythonUtils.setup_python_cache_dir(TaskMonitor.DUMMY)
                
                # Indicate that we've initialized the python environment, which should only happen once.
                self.python_initialized = True
            except Exception as e:
                Msg.show_error("Python error", "Problem getting Ghirda Python interpreter", str(e))
                return None
        
        state = PySystemState()
        state.ps1 = '>>> '
        state.ps2 = "... "
        
        # Return a new instance of our interpreter.
        return self.__init__(state)

    def __init__(self, state):
        super().__init__(None, state)
        
        # Store the default python path in case we need to reset it later.
        self.default_python_path = list(state.path)
        for obj in state.path:
            self.default_python_path.append(Py.new_string_or_unicode(obj.__str__()))
        
        # Allow interruption of python code to occur when various code paths are encountered.
        self.interrupt_trace_function = InterruptTraceFunction()
        
        # Setup __main__ module
        mod = imp.add_module('__main__')
        set_locals(mod.__dict__)
        
        # Load site.py (standard Python practice). This will also load our sitecustomize.py module.
        imp.load('site')
        
        # Setup code completion module.
        # Note that this is not exported to the global address space by default.
        self.introspect_module = imp.load('jintrospect')
        
        # Add __builtin__ module for code completion
        self.builtin_module = imp.load('__builtin__')
        
        self.initialize_python_path()

    def initialize_python_path(self):
        # Restore the python path back to default.
        state.path.retain_all(self.default_python_path)
        
        # Add in Ghidra script source directories
        for resource_file in GhidraScriptUtil.get_script_source_directories():
            state.path.append(Py.new_string_or_unicode(resource_file.file(false).getAbsolutePath()))
        
        # Add in the PyDev remote debugger module.
        if not SystemUtilities.is_in_development_mode() and not SystemUtilities.is_headless_mode():
            file = PyDevUtils.get_pydev_src_dir()
            if file is not None:
                state.path.append(Py.new_string_or_unicode(file.getAbsolutePath()))

    def push(self, line, script):
        if self.cleaned_up:
            raise IllegalStateException("Ghidra python interpreter has already been cleaned up.")
        
        inject_script_hierarchy(script)
        
        if buffer.length() > 0:
            buffer.append('\n')
        buffer.append(line)
        Py.get_thread_state().tracefunc = self.interrupt_trace_function
        try:
            more = runsource(buffer.__str__(), 'python')
            get_system_state().stderr.invoke('flush')
            if not more:
                resetbuffer()
        except PyException as e:
            resetbuffer()
            raise
        
    def exec_file(self, file, script):
        if self.cleaned_up:
            raise IllegalStateException("Ghidra python interpreter has already been cleaned up.")
        
        inject_script_hierarchy(script)
        
        # The Python import system sets the __file__ attribute to the file it's executing
        set_variable('__file__', Py.new_string_or_unicode(file.getAbsolutePath()))
        
    def print_err(self, str):
        try:
            get_system_state().stderr.invoke('write', Py.new_string_or_unicode(str + '\n'))
            get_system_state().stderr.invoke('flush')
        except PyException as e:
            Msg.error("Failed to write to stderr", str(e))

    # ... (rest of the methods)

class InterruptTraceFunction:
    def check_interrupt(self):
        if self.interrupt is not None:
            raise Py.make_exception(self.interrupt)
        
    def trace_call(self, frame):
        self.check_interrupt()
        return this
    
    def trace_return(self, frame, ret):
        self.check_interrupt()
        return this
    
    def trace_line(self, frame, line):
        self.check_interrupt()
        return this
    
    def trace_exception(self, frame, exc):
        self.check_interrupt()
        return this

class PySystemState:
    pass
