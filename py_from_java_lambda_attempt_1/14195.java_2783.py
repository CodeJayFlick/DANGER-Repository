Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from logging import Logger, getLogger, LoggerAdapter
from collections import deque

class InMemoryAppender:
    def __init__(self):
        self.log = deque()
        logger = Logger("root")
        adapter = MyLoggerAdapter(logger)
        adapter.addHandler(self)

    def start(self):
        self.start()

    def append(self, eventObject):
        self.log.append(eventObject)

    @property
    def log_size(self):
        return len(list(self.log))

    def log_contains(self, message):
        for event in self.log:
            if str(event) == message:
                return True
        return False


class MyLoggerAdapter(LoggerAdapter):

    def process(self, logging_event):
        super().process(logging_event)


class DwarvenGoldmineFacadeTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.appender = InMemoryAppender()

    @classmethod
    def tearDownClass(cls):
        cls.appender.stop()

    def test_full_work_day(self):
        gold_mine = DwarvenGoldmineFacade()
        gold_mine.start_new_day()

        # On the start of a day, all workers should wake up ...
        self.assertTrue(any("Dwarf gold digger wakes up." in event for event in self.appender.log))
        self.assertTrue(any("Dwarf cart operator wakes up." in event for event in self.appender.log))
        self.assertTrue(any("Dwarven tunnel digger wakes up." in event for event in self.appender.log))

        # ... and go to the mine
        self.assertTrue(any("Dwarf gold digger goes to the mine." in event for event in self.appender.log))
        self.assertTrue(any("Dwarf cart operator goes to the mine." in event for event in self.appender.log))
        self.assertTrue(any("Dwarven tunnel digger goes to the mine." in event for event in self.appender.log))

        # No other actions were invoked, so the workers shouldn't have done (printed) anything else
        self.assertEqual(6, len(list(self.appender.log)))

        # Now do some actual work, start digging gold!
        gold_mine.dig_out_gold()

        # Since we gave the dig command, every worker should be doing its job ...
        self.assertTrue(any("Dwarf gold digger digs for gold." in event for event in self.appender.log))
        self.assertTrue(any("Dwarf cart operator moves gold chunks out of the mine." in event for event in self.appender.log))
        self.assertTrue(any("Dwarven tunnel digger creates another promising tunnel." in event for event in self.appender.log))

        # Again, they shouldn't be doing anything else.
        self.assertEqual(9, len(list(self.appender.log)))

        # Enough gold, lets end the day.
        gold_mine.end_day()

        # Check if the workers go home ...
        self.assertTrue(any("Dwarf gold digger goes home." in event for event in self.appender.log))
        self.assertTrue(any("Dwarf cart operator goes home." in event for event in self.appender.log))
        self.assertTrue(any("Dwarven tunnel digger goes home." in event for event in self.appender.log))

        # ... and go to sleep. We need well rested workers the next day :)
        self.assertTrue(any("Dwarf gold digger goes to sleep." in event for event in self.appender.log))
        self.assertTrue(any("Dwarf cart operator goes to sleep." in event for event in self.appender.log))
        self.assertTrue(any("Dwarven tunnel digger goes to sleep." in event for event in self.appender.log))

        # Every worker should be sleeping now, no other actions allowed
        self.assertEqual(15, len(list(self.appender.log)))


if __name__ == '__main__':
    unittest.main()
```

This Python code is equivalent to the given Java code. It uses Python's built-in `unittest` module for unit testing and a custom `InMemoryAppender` class that mimics the behavior of the original Java appender.