Here is the translation of the given Java code into equivalent Python:

```Python
class AoutHeaderFactory:
    @staticmethod
    def create_aout_header(reader: 'BinaryReader', header: 'CoffFileHeader') -> 'AoutHeader':
        if header.optional_header_size == 0:
            return None

        match header.magic:
            case CoffMachineType.IMAGE_FILE_MACHINE_R3000:
                return AoutHeaderMIPS(reader)
            case _:
                return AoutHeader(reader)

class BinaryReader:
    pass

class CoffFileHeader:
    def __init__(self):
        self.optional_header_size = 0
        self.magic = None

class AoutHeader:
    def __init__(self, reader: 'BinaryReader'):
        pass

class AoutHeaderMIPS(AoutHeader):
    def __init__(self, reader: 'BinaryReader'):
        super().__init__(reader)
```

Please note that Python does not have a direct equivalent to Java's `switch` statement. Instead, we use the built-in `match` and `case` statements in Python 3.10 or later versions. If you are using an earlier version of Python, you can achieve similar functionality with if-elif-else blocks.

Also note that I've used type hints for function parameters and return types to make it easier to understand what each method is expecting as input and returning.