import unittest

class StatueTest(unittest.TestCase):
    def setUpClass(cls):
        cls.statue = Statue(1, 20)

    def tearDownClass(cls):
        cls.statue = None

    @unittest.skip("Not implemented yet")
    def test_update_for_pending_shoot(self):
        self.statue.frames = 10
        self.statue.update()
        self.assertEqual(11, self.statue.frames)

    @unittest.skip("Not implemented yet")
    def test_update_for_shooting(self):
        self.statue.frames = 19
        self.statue.update()
        self.assertEqual(0, self.statue.frames)
