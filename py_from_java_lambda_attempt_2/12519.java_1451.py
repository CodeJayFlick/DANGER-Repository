Here is the translation of the Java code into equivalent Python:

```Python
class AutoParameterImpl:
    def __init__(self, data_type: object, ordinal: int, storage: str, function: object) -> None:
        super().__init__(get_auto_name(storage), ordinal, data_type, storage, False, function.get_program(), 'ANALYSIS')
        if (storage.is_forced_indirect() or not storage.is_auto_storage()):
            raise ValueError("Improper auto storage specified")
        self.function = function

    def get_function(self) -> object:
        return self.function


def get_auto_name(auto_param_type: str) -> str:
    if auto_param_type is None:
        raise ValueError("storage does not correspond to an auto-parameter")
    return auto_param_type.get_display_name()


class InvalidInputException(Exception):
    pass

class AutoParameterImpl:
    def set_data_type(self, type: object, storage: str, force: bool = False, source: str = 'ANALYSIS') -> None:
        raise InvalidInputException("Auto-parameter may not be modified")

    def set_comment(self, comment: str) -> None:
        # Auto-parameter may not be modified
        pass

    def set_name(self, name: str, source: str) -> None:
        raise InvalidInputException("Auto-parameter may not be modified")
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, Python is dynamically typed language and it doesn't require explicit type declarations like in Java.