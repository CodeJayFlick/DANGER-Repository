import unittest
from game_controller import GameController

class TestGameController(unittest.TestCase):

    def setUp(self):
        self.controller = GameController()

    def tearDown(self):
        self.controller = None

    @unittest.skip("This test needs implementation")
    def test_move_bullet(self):
        self.controller.move_bullet(1.5)
        self.assertAlmostEqual(self.controller.bullet.position, 1.5)

    @unittest.skip("This test needs implementation")
    def test_get_bullet_position(self):
        self.assertAlmostEqual(self.controller.get_bullet_position(), self.controller.bullet.position)


if __name__ == '__main__':
    unittest.main()
