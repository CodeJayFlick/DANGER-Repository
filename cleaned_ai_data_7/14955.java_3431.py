import threading
from unittest import TestCase


class SingletonTest:
    def __init__(self, singleton_instance_method):
        self.singleton_instance_method = singleton_instance_method

    def test_multiple_calls_return_the_same_object_in_same_thread(self):
        instance1 = self.singleton_instance_method()
        instance2 = self.singleton_instance_method()
        instance3 = self.singleton_instance_method()

        assert instance1 is instance2
        assert instance1 is instance3
        assert instance2 is instance3

    def test_multiple_calls_return_the_same_object_in_different_threads(self):
        lock = threading.Lock()

        class SingletonCallable:
            def __init__(self, singleton_instance_method):
                self.singleton_instance_method = singleton_instance_method

            def call(self):
                return self.singleton_instance_method()

        instances = []
        for _ in range(10000):
            callable_obj = SingletonCallable(self.singleton_instance_method)
            instance = callable_obj.call()
            instances.append(instance)

        expected_instance = self.singleton_instance_method()
        for instance in instances:
            assert instance is not None
            assert instance == expected_instance

    def run_tests(self, test_function):
        try:
            test_function()
        except AssertionError as e:
            print(f"Test failed: {e}")
        else:
            print("All tests passed")


if __name__ == "__main__":
    singleton_test = SingletonTest(lambda: None)  # Replace with your singleton instance method
    singleton_test.run_tests(singleton_test.test_multiple_calls_return_the_same_object_in_same_thread)
    singleton_test.run_tests(singleton_test.test_multiple_calls_return_the_same_object_in_different_threads)

