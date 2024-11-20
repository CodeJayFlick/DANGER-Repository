Here is the translation of the Java code to Python:
```
import unittest

class SquareNumberRequestTest(unittest.TestCase):

    def test_delayed_squaring(self):
        consumer = Consumer(10)
        square_number_request = SquareNumberRequest(5)

        square_number_request.delayed_squaring(consumer)

        self.assertEqual(35, consumer.get_sum_of_squared_numbers())

if __name__ == '__main__':
    unittest.main()
```
Note that I've used the `unittest` module to define a test case and test method. The rest of the code is similar in structure to the Java original.

Here's a brief explanation of the translation:

* The copyright notice at the top is not translated, as it's not relevant to the Python code.
* The package declaration (`package com.iluwatar.fanout.fanin;`) is not needed in Python, so I omitted it.
* The imports are simplified: `org.junit.jupiter.api.Assertions` becomes just `unittest`, and `org.junit.jupiter.api.Test` becomes an empty decorator (since we're using the built-in `unittest` module).
* The Java class declaration (`class SquareNumberRequestTest`) is replaced with a Python class definition (`class SquareNumberRequestTest(unittest.TestCase):`).
* The test method signature (`@Test void delayedSquaringTest()`) is simplified to just `def test_delayed_squaring(self)`.
* The code inside the test method remains largely unchanged, except for some minor syntax adjustments (e.g., using `.get()` instead of `.getSumOfSquaredNumbers().get()`).
* Finally, I added a call to `unittest.main()` at the end to run the tests.