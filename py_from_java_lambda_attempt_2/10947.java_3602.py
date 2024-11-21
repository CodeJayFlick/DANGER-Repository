Here is the translation of the given Java code into equivalent Python:

```Python
class InvalidIMGLink:
    def __init__(self, img: 'IMG', message: str):
        self.img = img
        self.message = message
        if os.environ.get('GHIDRA_HELP_FAILFAST') == 'True':
            raise RuntimeError(f"{message}: {img}")

    @property
    def img(self) -> 'IMG':
        return self._img

    @img.setter
    def img(self, value: 'IMG'):
        self._img = value

    @property
    def message(self) -> str:
        return self._message

    @message.setter
    def message(self, value: str):
        self._message = value

    def identity_hash_code(self) -> int:
        return hash(self.img)

    def get_line_number(self) -> int:
        return self.img.get_line_number()

    def get_source_file(self) -> Path:
        return self.img.get_source_file()

    def compare_to(self, other: 'InvalidLink') -> int:
        if not isinstance(other, InvalidIMGLink):
            return 1
        other_link = other
        class_name = type(self).__name__
        other_class_name = type(other).__name__
        result = class_name.casefold().compare(to=other_class_name.casefold())
        if result != 0:
            return -result
        return self.img.compare_to(other_link.img)

    def __str__(self) -> str:
        return f"{self.message} -\n\tlink: {self.img}\n\tfrom file: {self.get_source_file_info()}"

    def get_source_file_info(self) -> str:
        line_number = self.img.get_line_number()
        return f"{self.img.get_source_file().to_uri()} (line:{line_number})"

    def __hash__(self) -> int:
        prime = 31
        result = 1
        if self.img is None:
            result *= 0
        else:
            result *= hash(self.img)
        if self.message is None:
            result *= 0
        else:
            result *= hash(self.message)
        return result

    def __eq__(self, other: object) -> bool:
        if self == other:
            return True
        if other is None or not isinstance(other, InvalidIMGLink):
            return False
        other_link = other
        if self.img != other_link.img:
            return False
        if self.message != other_link.message:
            return False
        return True

class IMG:  # This class should be defined elsewhere in your codebase.
    def get_line_number(self) -> int:
        pass

    def get_source_file(self) -> Path:
        pass

from pathlib import Path
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation.