import unittest

class LockingException(Exception):
    def __init__(self, message):
        super().__init__(message)

def test_exception():
    try:
        raise LockingException("test")
    except LockingException as e:
        assert e.args[0] == "test"

if __name__ == "__main__":
    unittest.main()
