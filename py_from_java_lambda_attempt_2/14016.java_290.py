Here is the translation of the given Java code into Python:

```Python
import unittest
from logging import Logger, getLogger, WARNING
from collections import deque

class SimpleTroll:
    def __init__(self):
        self.attack_power = 10

    def attack(self):
        print("The troll tries to grab you!")

    def flee_battle(self):
        print("The troll shrieks in horror and runs away!")


class InMemoryAppender:
    def __init__(self, clazz):
        logger = getLogger(str(clazz))
        self.logger = logger
        self.log = deque()

    def start(self):
        self.logger.addHandler(self)

    def stop(self):
        self.logger.removeHandler(self)

    def append(self, eventObject):
        self.log.append(eventObject.getMessage())

    @property
    def last_message(self):
        return self.log[-1]

    @property
    def log_size(self):
        return len(self.log)


class TestSimpleTroll(unittest.TestCase):

    def setUp(self):
        self.appender = InMemoryAppender(SimpleTroll)

    def tearDown(self):
        self.appender.stop()

    def test_troll_actions(self):
        troll = SimpleTroll()
        self.assertEqual(troll.attack_power, 10)
        
        troll.attack()
        self.assertEqual(self.appender.last_message, "The troll tries to grab you!")

        troll.flee_battle()
        self.assertEqual(self.appender.last_message, "The troll shrieks in horror and runs away!")
        
        self.assertEqual(len(self.appender.log), 3)


if __name__ == '__main__':
    unittest.main()
```

This Python code is equivalent to the given Java code. It includes a `SimpleTroll` class with methods for attack and flee, an `InMemoryAppender` class that logs messages from these actions, and a test case using the `unittest` module in Python.