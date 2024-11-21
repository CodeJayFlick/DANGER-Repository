class WizardTest:
    def test_to_string(self):
        names = ["Gandalf", "Dumbledore", "Oz", "Merlin"]
        for name in names:
            self.assertEqual(name, str(Wizard(name)))

if __name__ == "__main__":
    import unittest
    class Test(unittest.TestCase, WizardTest):
        pass

    if __name__ == "__main__":
        unittest.main()
