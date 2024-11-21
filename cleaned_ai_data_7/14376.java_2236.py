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
