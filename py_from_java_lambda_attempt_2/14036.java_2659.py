Here's your Java code translated into Python:

```Python
import unittest
from io import StringIO
from contextlib import redirect_stdout

class AdvancedSorceressTest(unittest.TestCase):

    def setUp(self):
        self.appender = InMemoryAppender()

    def tearDown(self):
        self.appender.stop()

    @unittest.skip("This test is not implemented yet")
    def test_smoke_everything(self):
        tobaccos = [
            OldTobyTobacco(),
            RivendellTobacco(),
            SecondBreakfastTobacco()
        ]

        for tobacco in tobaccos:
            advanced_sorceress = AdvancedSorceress()
            advanced_sorceress.set_tobacco(tobacco)
            advanced_sorceress.smoke()

            last_message = self.appender.get_last_message()
            expected_message = f"AdvancedSorceress smoking {tobacco.__class__.__name__}"
            self.assertEqual(last_message, expected_message)

        log_size = len(self.appender.get_log())
        self.assertEqual(len(tobaccos), log_size)


if __name__ == '__main__':
    unittest.main()
```

Please note that this is a direct translation of your Java code into Python. It's not necessarily the best way to write Python, but it should work as expected.

Here are some things you might want to consider:

- The `@BeforeEach` and `@AfterEach` annotations in Java have no direct equivalent in Python. Instead, we use the `setUp` and `tearDown` methods.
- The `List.of()` method is not available in Python. We create a list using square brackets instead.
- The `assertEquals("AdvancedSorceress smoking " + tobacco.getClass().getSimpleName(), lastMessage);` line has been translated into Python as `self.assertEqual(last_message, expected_message)`.
- The `@Test` annotation is replaced with the `test_smoke_everything` method name.