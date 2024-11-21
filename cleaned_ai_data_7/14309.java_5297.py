# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import unittest

class ApplicationExceptionTest(unittest.TestCase):
    def test_cause(self):
        cause = Exception()
        self.assertEqual(cause, ApplicationException(cause).get_cause())

if __name__ == '__main__':
    unittest.main()
