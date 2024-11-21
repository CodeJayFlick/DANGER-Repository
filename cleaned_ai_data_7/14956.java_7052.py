import unittest
from singleton import ThreadSafeDoubleCheckLocking


class TestThreadSafeDoubleCheckLocking(unittest.TestCase):

    def setUp(self):
        pass  # No need to create an instance here as it's already created in SingletonTest

    def test_creating_new_instance_by_reflection(self):
        try:
            constructor = type(ThreadSafeDoubleCheckLocking).__dict__.get('__init__', None)
            if not callable(constructor):
                raise TypeError("Expected a function")
            self.assertRaises(TypeError, constructor)


if __name__ == '__main__':
    unittest.main()
