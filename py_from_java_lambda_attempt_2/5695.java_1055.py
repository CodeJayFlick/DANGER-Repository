Here is the translation of the Java interface `GFileSystemProgramProvider` to Python:
```python
class GFileSystemProgramProvider:
    def get_program(self, file: 'ghidra.GFile', language_service: 'ghidra.LanguageService',
                    monitor: 'ghidra.TaskMonitor', consumer: object) -> 'ghidra.Program':
        # NOTE: ONLY OVERRIDE THIS METHOD IF YOU CANNOT PROVIDE AN INPUT STREAM
        # TO THE INTERNAL FILES OF THIS FILE SYSTEM!
        raise NotImplementedError

    def can_provide_program(self, file: 'ghidra.GFile') -> bool:
        return False  # default implementation returns False
```
Note that I've used type hints to indicate the expected types of the method parameters and return values. In Python, these are not enforced at runtime, but they do provide a way to document the code's intent.

Also, since this is an interface in Java, there is no equivalent concept in Python (which does not have interfaces). Instead, I've defined a class `GFileSystemProgramProvider` that provides the same methods as the original Java interface.