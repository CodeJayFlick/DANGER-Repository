Here is the translation of the Java code to Python:
```
import unittest
from unittest.mock import patch, Mock

class DragonSlayerTest(unittest.TestCase):
    def test_go_to_battle(self):
        strategy = Mock()
        dragon_slayer = DragonSlayer(strategy)

        with patch.object(strategy, 'execute') as execute_mock:
            dragon_slayer.go_to_battle()
            execute_mock.assert_called_once()

    def test_change_strategy(self):
        initial_strategy = Mock()
        dragon_slayer = DragonSlayer(initial_strategy)

        with patch.object(initial_strategy, 'execute') as execute_mock:
            dragon_slayer.go_to_battle()
            execute_mock.assert_called_once()

        new_strategy = Mock()
        dragon_slayer.change_strategy(new_strategy)
        dragon_slayer.go_to_battle()
        strategy.execute().assert_called_once()

class DragonSlayer:
    def __init__(self, strategy):
        self.strategy = strategy

    def go_to_battle(self):
        self.strategy.execute()

    def change_strategy(self, new_strategy):
        self.strategy = new_strategy
```
Note that I used the `unittest` module for testing and the `mock` library from `unittest.mock` to create mock objects. The rest of the code is a direct translation of the Java code to Python.

Also, in Python, we don't need to specify types or use explicit casting like you would do with Java's generics.