Here is the translation of the Java code to Python:
```
import unittest

class PlayerDetailsTest(unittest.TestCase):
    def test_equals(self):
        details1 = PlayerDetails("tom@foo.bar", "11212-123434", "+12323425")
        details2 = PlayerDetails("tom@foo.bar", "11212-123434", "+12323425")
        self.assertEqual(details1, details2)
        details3 = PlayerDetails("john@foo.bar", "16412-123439", "+34323432")
        self.assertNotEqual(details1, details3)

class PlayerDetails:
    def __init__(self, email, phone_number, country_code):
        self.email = email
        self.phone_number = phone_number
        self.country_code = country_code

if __name__ == '__main__':
    unittest.main()
```
Note that I've used the `unittest` module to write unit tests in Python. The test case is similar to the Java code, but with some minor differences due to language-specific syntax and semantics.

Also, I've defined a separate class `PlayerDetails` to represent the player details object, which has attributes for email, phone number, and country code.