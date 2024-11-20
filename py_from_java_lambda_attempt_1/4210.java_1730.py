Here is a translation of the Java code into equivalent Python:

```Python
class Pe64RelocationFixupHandler:
    def process_relocation(self, program: 'Program', relocation: 'Relocation', old_image_base: int, new_image_base: int) -> bool:
        return self.process_64_bit_relocation(program, relocation, old_image_base, new_image_base)

    def handles_program(self, program: 'Program') -> bool:
        if not isinstance(program.get_executable_format(), str):
            return False
        language = program.get_language()
        if len(language.get_language_description()) != 64:
            return False
        processor = language.get_processor()
        return processor == "x86"


class Program:
    def __init__(self, executable_format: str, language: 'Language', *args):
        self.executable_format = executable_format
        self.language = language

    @property
    def get_executable_format(self) -> str:
        return self.executable_format


class Language:
    def __init__(self, language_description: bytes, processor: str, *args):
        self.language_description = language_description
        self.processor = processor

    @property
    def get_language_description(self) -> bytes:
        return self.language_description

    @property
    def get_processor(self) -> str:
        return self.processor


class Relocation:
    pass


# Usage example:

program = Program("PE", Language(b"64-bit language description", "x86"))
relocation = Relocation()
fixup_handler = Pe64RelocationFixupHandler()

print(fixup_handler.process_relocation(program, relocation, 0, 1))
print(fixup_handler.handles_program(program))
```

Please note that Python does not have direct equivalent of Java's classes and interfaces. It has modules and functions instead.