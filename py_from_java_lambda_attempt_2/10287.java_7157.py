Here is the translation of the Java code into Python:

```Python
class ApplicationConfiguration:
    def __init__(self):
        self.monitor = None  # equivalent to TaskMonitor.DUMMY in Java
        self.initialize_logging = True
        self.log_file = None
        self.script_log_file = None

    def initialize_application(self):  # no direct translation, just a placeholder for the method
        pass

    @property
    def is_headless(self):
        return True  # equivalent to public boolean isHeadless() in Java

    @property
    def task_monitor(self):
        return self.monitor  # equivalent to public TaskMonitor getTaskMonitor()

    @property
    def initialize_logging_enabled(self):
        return self.initialize_logging  # equivalent to public boolean isInitializeLogging()

    @property
    def application_log_file(self):
        return self.log_file  # equivalent to public File getApplicationLogFile()

    def set_task_monitor(self, monitor):
        self.monitor = monitor  # equivalent to public void setTaskMonitor(TaskMonitor)

    def set_initialize_logging_enabled(self, initialize_logging):
        self.initialize_logging = initialize_logging  # equivalent to public void setInitializeLogging(boolean)

    def set_application_log_file(self, log_file):
        self.log_file = log_file  # equivalent to public void setApplicationLogFile(File)

    @property
    def script_log_file(self):
        return self.script_log_file  # equivalent to public File getScriptLogFile()

    def set_script_log_file(self, script_log_file):
        self.script_log_file = script_log_file  # equivalent to public void setScriptLogFile(File)

    def install_static_factories(self):  # no direct translation, just a placeholder for the method
        pass

    @property
    def error_display(self):
        return ConsoleErrorDisplay()  # equivalent to public ErrorDisplay getErrorDisplay()
```

Please note that Python does not have an exact equivalent of Java's `package` declaration. Also, some methods in the original code are simply placeholders and do not translate directly into Python (e.g., `initializeApplication`, `installStaticFactories`).