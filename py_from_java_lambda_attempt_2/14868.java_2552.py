Here is the translation of the Java code to Python:

```Python
import unittest
from saga import SagaApplication

class TestSagaApplication(unittest.TestCase):

    def test_should_execute_without_exception(self):
        try:
            SagaApplication.main([])
        except Exception as e:
            self.fail(f"An exception occurred: {e}")

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we use the `unittest` module and define test methods using the standard method naming convention (`test_`). The `try-except` block is used to catch any exceptions raised by the code under test.