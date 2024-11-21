import unittest
from logging import Logger, getLogger, DEBUG
from io import StringIO
import re


class InMemoryAppender:
    def __init__(self):
        self.log = []
        logger = getLogger("root")
        logger.addHandler(self)
        self.start()

    def start(self):
        pass

    def stop(self):
        pass

    def append(self, eventObject):
        self.log.append(eventObject)

    def log_contains(self, message):
        return any(re.search(message, str(event)) for event in self.log)


class ClosableTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.appender = InMemoryAppender()

    @classmethod
    def tearDownClass(cls):
        cls.appender.stop()


    def test_open_close(self):
        with SlidingDoor() as sliding_door, TreasureChest() as treasure_chest:
            self.assertTrue(any("Sliding door opens." in str(event) for event in self.appender.log))
            self.assertTrue(any("Treasure chest opens." in str(event) for event in self.appender.log))

        self.assertTrue(any("Treasure chest closes." in str(event) for event in self.appender.log))
        self.assertTrue(any("Sliding door closes." in str(event) for event in self.appender.log))


if __name__ == '__main__':
    unittest.main()
