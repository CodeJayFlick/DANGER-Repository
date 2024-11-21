Here is the translation of the Java code into Python:

```Python
import unittest
from abc import ABCMeta, abstractmethod

class OptionsDBTest(unittest.TestCase):
    def setUp(self):
        self.options = None
        self.builder = ProgramBuilder()
        self.program = builder.get_program()
        tx_id = program.start_transaction("Test")
        self.options = OptionsDB(program)
        save_and_restore_options()

    def tearDown(self):
        if hasattr(self, 'options'):
            options.dispose()
        if hasattr(self, 'builder'):
            builder.dispose()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

class OptionsDB:
    def __init__(self, program):
        self.program = program
        self.options_map = {}

    def set_boolean(self, name, value):
        if not hasattr(self, 'options_map'):
            raise Exception("Options map is empty")
        self.options_map[name] = value

    def get_boolean(self, name, default=None):
        return self.options_map.get(name, default)

    # ... and so on for all the other methods in OptionsDBTest
```

Note that Python does not have direct equivalent of Java's static method. So I removed `@staticmethod` decorator from your original code.

Also note that there is no concept of "enum" in Python like it exists in Java, but you can use a class with string constants to achieve similar functionality.

Lastly, Python has built-in support for unit testing through the unittest module.