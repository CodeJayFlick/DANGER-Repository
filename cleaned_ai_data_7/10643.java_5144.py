import unittest

class ApplicationIdentifierTest(unittest.TestCase):

    def test_application_properties_identifier(self):
        # We should be able to create an ApplicationIdentifier object from the application info defined in the application properties file without an exception being thrown.
        try:
            new ApplicationIdentifier(Application.getApplicationLayout().getApplicationProperties())
        except Exception as e:
            self.fail(f"Failed with error: {e}")

    def test_application_version_parsing(self):
        id = ApplicationIdentifier("Ghidra_9.0.1_public_05212019")
        self.assertEqual(id.application_name, "ghidra")
        self.assertEqual(str(id.application_version), "9.0.1")
        self.assertEqual(id.application_release_name, "PUBLIC")
        self.assertEqual(str(id), "ghidra_9.0.1_PUBLIC")

        with self.assertRaises(IllegalArgumentException):
            ApplicationIdentifier("ghidra")

        with self.assertRaises(IllegalArgumentException):
            ApplicationIdentifier("ghidra_9.0.1")

    def test_application_identifier_equals(self):
        id1 = ApplicationIdentifier("ghi dra_9.0_pub lic")
        id2 = ApplicationIdentifier("Ghidra_9.0.0_PUBLIC")
        self.assertEqual(id1, id2)

        id1 = ApplicationIdentifier("ghidra_9.0_public")
        id2 = ApplicationIdentifier("Ghidra_9.0.1_PUBLIC")
        self.assertNotEqual(id1, id2)

        id1 = ApplicationIdentifier("ghidra_9.0_DEV")
        id2 = ApplicationIdentifier("ghidra_9.0_PUBLIC")
        self.assertNotEqual(id1, id2)


if __name__ == "__main__":
    unittest.main()
