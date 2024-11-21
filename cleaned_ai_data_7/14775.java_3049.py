import unittest
from unittest.mock import patch
from io import StringIO
import logging


class WizardTowerProxyTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.appender = InMemoryAppender()

    @classmethod
    def tearDownClass(cls):
        cls.appender.stop()

    def setUp(self):
        self.appender.reset()
        self.wizards = [
            Wizard("Gandalf"),
            Wizard("Dumbledore"),
            Wizard("Oz"),
            Wizard("Merlin")
        ]

    def test_enter(self):
        proxy = WizardTowerProxy(IvoryTower())
        for wizard in self.wizards:
            proxy.enter(wizard)

        log_contents = self.appender.get_log()
        self.assertIn("Gandalf enters the tower.", log_contents)
        self.assertIn("Dumbledore enters the tower.", log_contents)
        self.assertIn("Oz enters the tower.", log_contents)
        self.assertIn("Merlin is not allowed to enter!", log_contents)
        self.assertEqual(4, len(log_contents.splitlines()))


class Wizard:
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return f"{self.name}"


class IvoryTower:
    pass


class InMemoryAppender:

    def reset(self):
        self.log = ""

    def stop(self):
        pass

    def get_log(self):
        return self.log.splitlines()

    def logContains(self, message):
        return message in self.get_log()


if __name__ == '__main__':
    unittest.main()
