class Skeleton:
    def __init__(self, initial_position):
        self.position = initial_position
        self.patrolling_left = False

    def set_position(self, position):
        self.position = position

    def update(self):
        if self.patrolling_left and self.position > 0:
            self.set_position(self.position - 1)
        elif not self.patrolling_left and self.position < 100:
            self.set_position(self.position + 1)

class TestSkeleton(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.skeleton = Skeleton(1)

    @classmethod
    def tearDownClass(cls):
        cls.skeleton = None

    def test_update_for_patrolling_left(self):
        self.skeleton.patrolling_left = True
        self.skeleton.set_position(50)
        self.skeleton.update()
        self.assertEqual(self.skeleton.position, 49)

    def test_update_for_patrolling_right(self):
        self.skeleton.patrolling_left = False
        self.skeleton.set_position(50)
        self.skeleton.update()
        self.assertEqual(self.skeleton.position, 51)

    def test_update_for_reverse_direction_from_left_to_right(self):
        self.skeleton.patrolling_left = True
        self.skeleton.set_position(1)
        self.skeleton.update()
        self.assertEqual(self.skeleton.position, 0)
        self.assertFalse(self.skeleton.patrolling_left)

    def test_update_for_reverse_direction_from_right_to_left(self):
        self.skeleton.patrolling_left = False
        self.skeleton.set_position(99)
        self.skeleton.update()
        self.assertEqual(self.skeleton.position, 100)
        self.assertTrue(self.skeleton.patrolling_left)


if __name__ == '__main__':
    unittest.main()
