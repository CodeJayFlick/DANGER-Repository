Here is the translation of the given Java code into equivalent Python:

```Python
class WrapIDebugClient2:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def write_dump_file2(self, dump_file, qualifier, format_flags, comment):
        # Assuming _invokeHR is a function that invokes the WriteDumpFile2 method
        return self._invoke_hr(0x0001, self.pv_instance, dump_file, qualifier, format_flags, comment)

    def add_dump_information_file(self, info_file, type):
        # Assuming _invokeHR is a function that invokes the AddDumpInformationFile method
        return self._invoke_hr(0x0002, self.pv_instance, info_file, type)

    def end_process_server(self, server):
        # Assuming _invokeHR is a function that invokes the EndProcessServer method
        return self._invoke_hr(0x0003, self.pv_instance, server)

    def wait_for_process_server_end(self, timeout):
        # Assuming _invokeHR is a function that invokes the WaitForProcessServerEnd method
        return self._invoke_hr(0x0004, self.pv_instance, timeout)

    def is_kernel_debugger_enabled(self):
        # Assuming _invokeHR is a function that invokes the IsKernelDebuggerEnabled method
        return self._invoke_hr(0x0005, self.pv_instance)

    def terminate_current_process(self):
        # Assuming _invokeHR is a function that invokes the TerminateCurrentProcess method
        return self._invoke_hr(0x0006, self.pv_instance)

    def detach_current_process(self):
        # Assuming _invokeHR is a function that invokes the DetachCurrentProcess method
        return self._invoke_hr(0x0007, self.pv_instance)

    def abandon_current_process(self):
        # Assuming _invokeHR is a function that invokes the AbandonCurrentProcess method
        return self._invoke_hr(0x0008, self.pv_instance)
```

Note: This Python code assumes you have defined `_invoke_hr` as a function elsewhere in your program.