import unittest
from unittest.mock import patch

class VariableStepGameLoopTest(unittest.TestCase):

    def setUp(self):
        self.game_loop = VariableStepGameLoop()

    def tearDown(self):
        self.game_loop = None

    @patch('VariableStepGameLoop.update')
    def test_update(self, mock_update):
        self.game_loop.update(20)
        self.assertEqual(self.game_loop.controller.get_bullet_position(), 0.01)

if __name__ == '__main__':
    unittest.main()
