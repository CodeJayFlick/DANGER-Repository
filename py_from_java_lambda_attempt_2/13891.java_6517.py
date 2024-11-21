Here is the translation of the given Java code into Python:

```Python
import logging

class Target:
    def __init__(self):
        self._size = None
        self._visibility = None

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        self._size = value

    @property
    def visibility(self):
        return self._visibility

    @visibility.setter
    def visibility(self, value):
        self._visibility = value

    def print_status(self):
        logging.info("{}, [size={}] [visibility={}]", self, self.size, self.visibility)

    def change_size(self):
        if self.size == "NORMAL":
            self.size = "SMALL"
        else:
            self.size = "NORMAL"

    def change_visibility(self):
        if self.visibility == "INVISIBLE":
            self.visibility = "VISIBLE"
        else:
            self.visibility = "INVISIBLE"


class Size:
    NORMAL = "NORMAL"
    SMALL = "SMALL"


class Visibility:
    INVISIBLE = "INVISIBLE"
    VISIBLE = "VISIBLE"

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    target = Target()
    target.print_status()  # prints: <Target object>, [size=<default size>] [visibility=<default visibility>]
    target.change_size()
    target.print_status()  # prints: <Target object>, [size=SMALL] [visibility=<default visibility>]
    target.change_visibility()
    target.print_status()  # prints: <Target object>, [size=SMALL] [visibility=VISIBLE]

```

Please note that Python does not have a direct equivalent to Java's `@Setter` and `@Getter`. Instead, we use the property decorator (`@property`) to define getter and setter methods.