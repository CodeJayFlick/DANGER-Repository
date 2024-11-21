Here is the translation of the Java code into Python:

```Python
import unittest

class ApplicationVersionTest(unittest.TestCase):

    def test_application_properties_version(self):
        # We should be able to create an ApplicationVersion object from the application version defined in the application properties file without an exception being thrown.
        new ApplicationVersion(Application.getApplicationLayout().getApplicationProperties().getApplicationVersion())

    def test_application_version_parsing(self):
        self.assertEqual(str(ApplicationVersion("9.0")), "9.0")
        self.assertEqual(str(ApplicationVersion("9.0.0")), "9.0")
        self.assertEqual(str(ApplicationVersion("9.0.0-BETA")), "9.0- BETA")

        self.assertEqual(str(ApplicationVersion("9.1")), "9.1")
        self.assertEqual(str(ApplicationVersion("9.1.1")), "9.1.1")
        self.assertEqual(str(ApplicationVersion("9.1.1-BETA")), "9.1.1- BETA")

        try:
            ApplicationVersion("9")
            self.fail("Should not be able to parse only a major version...a minor version is required.")
        except ValueError:
            # Getting here indicates success
            pass

    def test_application_version_getters(self):
        application_version = ApplicationVersion("9.0.1-BETA")
        self.assertEqual(application_version.get_major(), 9)
        self.assertEqual(application_version.get_minor(), 0)
        self.assertEqual(application_version.get_patch(), 1)

    def test_application_version_equals(self):
        application_version1 = ApplicationVersion("9.0")
        application_version2 = ApplicationVersion("9.0.0")
        self.assertTrue(application_version1.equals(application_version2))

        application_version1 = ApplicationVersion("9.0")
        application_version2 = ApplicationVersion("9.0.0-BETA")
        self.assertFalse(application_version1.equals(application_version2))

        application_version1 = ApplicationVersion("9.0.0")
        application_version2 = ApplicationVersion("9.1")
        self.assertFalse(application_version1.equals(application_version2))

        application_version1 = ApplicationVersion("9.0")
        application_version2 = ApplicationVersion("10.0")
        self.assertNotEqual(application_version1, application_version2)

    def test_application_version_compare(self):
        application_version1 = ApplicationVersion("9.0")
        application_version2 = ApplicationVersion("9.0.0-BETA")
        self.assertEqual(application_version1.compare_to(application_version2), 0)

        application_version1 = ApplicationVersion("9.0")
        application_version2 = ApplicationVersion("10.0")
        self.assertLessThan(0, application_version1.compare_to(application_version2))

        application_version1 = ApplicationVersion("9.0")
        application_version2 = ApplicationVersion("9.1")
        self.assertLessThan(0, application_version1.compare_to(application_version2))

        application_version1 = ApplicationVersion("9.0.1")
        application_version2 = ApplicationVersion("9.0.2")
        self.assertLessThan(0, application_version1.compare_to(application_version2))


if __name__ == '__main__':
    unittest.main()
```

Note: The Python code is written in a way that it can be run as a standalone script using the `unittest` module from the standard library.