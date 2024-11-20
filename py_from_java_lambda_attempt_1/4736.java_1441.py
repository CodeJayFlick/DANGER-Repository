Here is the translation of the Java code to Python:
```
import collections

class ElfExtensionFactory:
    @classmethod
    def get_all_extensions(cls):
        return [cls._get_extension_instance() for _ in range(len(ElfExtension.__subclasses__()))]

    @classmethod
    def get_load_adapter(cls, elf_header: 'ElfHeader') -> 'ElfLoadAdapter':
        for handler in ElfExtensionFactory.get_all_extensions():
            if handler.can_handle(elf_header):
                return handler
        return None

class ElfExtension:
    pass

class ElfLoadAdapter:
    pass

class ElfHeader:
    pass
```
Note that I've used Python's type hinting system to indicate the types of variables and function parameters. This is not strictly necessary, but it can help with code readability and maintainability.

Also, in Python, we don't need a `private` keyword or an explicit constructor (i.e., `__init__()` method) like we do in Java. The class definition itself serves as the constructor.

The rest of the translation is straightforward: I've replaced Java's syntax with equivalent Python syntax for classes, methods, and variables.