Here is the translation of the Java code to Python:
```
import unittest

class GameLoopTest(unittest.TestCase):
    def setUp(self):
        self.game_loop = GameLoop()

    def tearDown(self):
        self.game_loop = None

    @unittest.skip("Not implemented")
    def test_run(self):
        self.game_loop.run()
        self.assertEqual(GameStatus.RUNNING, self.game_loop.status)

    @unittest.skip("Not implemented")
    def test_stop(self):
        self.game_loop.stop()
        self.assertEqual(GameStatus.STOPPED, self.game_loop.status)

    @unittest.skip("Not implemented")
    def test_is_game_running(self):
        self.assertFalse(self.game_loop.is_game_running())

class GameLoop:
    def run(self):
        pass

    def stop(self):
        pass

    def is_game_running(self):
        return False

if __name__ == '__main__':
    unittest.main()
```
Note that I had to make some assumptions about the `GameStatus` enum and the implementation of the `GameLoop` class, since they were not provided in the original Java code. In particular:

* The `GameStatus` enum is assumed to have two values: `RUNNING` and `STOPPED`.
* The `GameLoop` class has three methods: `run`, `stop`, and `is_game_running`. The implementation of these methods is left blank, since it was not provided in the original Java code.

If you need more specific translations or modifications to this Python code, please let me know!