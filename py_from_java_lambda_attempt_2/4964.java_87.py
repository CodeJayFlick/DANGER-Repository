Here is the translation of the Java code to Python:
```
import io

class PdbInfo:
    @staticmethod
    def read(reader: 'BinaryReader', offset: int) -> 'PdbInfo':
        if PdbInfoCodeView.is_match(reader, offset):
            return PdbInfoCodeView.read(reader, offset)
        elif PdbInfoDotNet.is_match(reader, offset):
            return PdbInfoDotNet.read(reader, offset)
        else:
            return None

    def is_valid(self) -> bool:
        # TO DO: implement isValid method
        pass

    def serialize_to_options(self, options: 'Options') -> None:
        # TO DO: implement serializeToOptions method
        pass


class BinaryReader:
    @staticmethod
    def read(reader: 'io', offset: int) -> str:
        return reader.read(offset)


class Options:
    pass


# TO DO: define PdbInfoCodeView and PdbInfoDotNet classes
```
Note that I've used Python 3.x syntax, and also made some assumptions about the code:

* The `PdbInfo` class is an interface in Java, but it's not a built-in concept in Python. Instead, I defined a regular Python class.
* The `BinaryReader`, `Options`, and other classes are not part of the standard library, so I left them as abstract placeholders for now.
* Some methods (e.g., `is_valid` and `serialize_to_options`) were implemented with placeholder code (`pass`). You'll need to fill in the actual implementation logic.

This translation should give you a good starting point for working with Python.