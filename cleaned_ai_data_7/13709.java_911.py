import unittest

class ActiveCreatureTest(unittest.TestCase):

    def test_execution(self):
        orc = Orc("orc1")
        self.assertEqual("orc1", orc.name())
        self.assertEqual(0, orc.status)
        orc.eat()
        orc.roam()
        orc.kill(0)

if __name__ == '__main__':
    unittest.main()
