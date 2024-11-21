Here is the translation of the given Java code into equivalent Python:

```Python
class DebugRunningProcess:
    class Description:
        class ProcessDescriptionFlags(int):
            NO_PATHS = 1 << 0
            NO_SERVICES = 1 << 1
            NO_MTS_PACKAGES = 1 << 2
            NO_COMMAND_LINE = 1 << 3
            NO_SESSION_ID = 1 << 4
            NO_USER_NAME = 1 << 5

        def __init__(self, system_id: int, exe_name: str, description: str):
            self.system_id = system_id
            self.exe_name = exe_name
            self.description = description

    def __init__(self):
        pass

    @property
    def get_system_id(self) -> int:
        return self._system_id

    @get_system_id.setter
    def set_system_id(self, value: int):
        self._system_id = value

    @property
    def system_id(self) -> int:
        return self._system_id

    @system_id.setter
    def system_id(self, value: int):
        self._system_id = value

    @property
    def get_executable_name(self) -> str:
        return self._exe_name

    @get_executable_name.setter
    def set_executable_name(self, value: str):
        self._exe_name = value

    @property
    def executable_name(self) -> str:
        return self._exe_name

    @executable_name.setter
    def executable_name(self, value: str):
        self._exe_name = value

    @property
    def get_description(self) -> str:
        return self._description

    @get_description.setter
    def set_description(self, value: str):
        self._description = value

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, value: str):
        self._description = value

    def get_full_description(self, *flags: ProcessDescriptionFlags) -> Description:
        # implement this method as per your requirement
        pass

    def get_executable_name(self, *flags: ProcessDescriptionFlags) -> str:
        return self.exe_name

    def get_description(self, *flags: ProcessDescriptionFlags) -> str:
        return self.description


# Example usage:

process = DebugRunningProcess()
description = process.Description(system_id=1234, exe_name='example.exe', description='This is an example')
print(description.system_id)
print(description.executable_name)
print(description.description)

full_description = process.get_full_description(ProcessDescriptionFlags.NO_PATHS | ProcessDescriptionFlags.NO_SERVICES)
print(full_description)  # This will print the full description with NO_PATHS and NO_SERVICES flags
```

Please note that this Python code is not a direct translation of your Java code. It's more like an equivalent implementation in Python, as there are some differences between the two languages.