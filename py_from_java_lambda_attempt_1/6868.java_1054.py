Here is the translation of the Java code into Python:

```Python
class FlatDecompilerAPI:
    def __init__(self):
        self.flat_program_api = None
        self.decompiler = None

    def initialize(self):
        if not self.decompiler:
            self.decompiler = Decompiler()
            program = self.flat_program_api.get_current_program()
            self.decompiler.open_program(program)

    def get_decompiler(self):
        return self.decompiler

    def decompile(self, function: 'Function', timeout_secs=0) -> str:
        if not self.decompiler:
            raise Exception("Decompiler is not initialized")

        try:
            results = self.decompiler.decompile_function(function, timeout_secs)
            res = results.get_decompiled_function()
            if not res:
                raise DecompileException("Decompiler", results.get_error_message())
            return res.get_code()
        except Exception as e:
            raise

    def dispose(self):
        if self.decompiler:
            self.decompiler.dispose()


class Decompiler:
    pass


class Function:
    pass


class FlatProgramAPI:
    def get_current_program(self) -> 'program.Program':
        pass
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. For example:

- The `Decompiler` class in the original Java code seems to have some methods (`decompileFunction`, etc.) which are missing from my translation.
- Similarly, the `FlatProgramAPI` class has several methods (`getMonitor`, `getCurrentProgram`, etc.) that I did not translate as they seem to be specific to your use case and may require additional information or modifications.

Also note that Python does not have direct equivalent of Java's `Disposable` interface. The `dispose()` method in the original code seems to release resources held by the decompiler, but this is not directly translatable into Python.