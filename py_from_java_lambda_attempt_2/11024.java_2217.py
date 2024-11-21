Here is the equivalent Python code:

```Python
import assertor

class AppInfo:
    _tool = None
    _active_project = None

    @classmethod
    def set_front_end_tool(cls, tool):
        cls._tool = tool

    @classmethod
    def set_active_project(cls, project):
        cls._active_project = project

    @classmethod
    def get_front_end_tool(cls):
        assertor.assert_that(cls._tool is not None)
        return cls._tool

    @classmethod
    def get_active_project(cls):
        return cls._active_project

    @classmethod
    def exit_ghidra(cls):
        assertor.assert_that(cls._tool is not None)
        cls._tool.exit()
```

Note that Python does not have a direct equivalent to Java's `assert` keyword. Instead, we use the `assertor` library which provides an assertion mechanism similar to Java's.