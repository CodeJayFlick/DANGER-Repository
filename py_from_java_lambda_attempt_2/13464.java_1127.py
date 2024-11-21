Here is the translation of the given Java code into equivalent Python:

```Python
import unittest

class PrintingPluginScreenShots:
    def __init__(self):
        pass

    @unittest.skip("Not implemented yet")
    def test_print_options(self):
        make_selection(0x0406c21, 0x0406c31)
        perform_action("Print", "PrintingPlugin", False)

        capture_dialog()

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation of the Java code into Python. However, there are some differences between the two languages:

1. In Python, we don't need to explicitly declare variables or methods like in Java.

2. The `@Test` annotation from JUnit is replaced with the `unittest.skip()` decorator which skips the test case for now (you can modify this as per your requirements).

3. Similarly, you would have to implement equivalent functions (`make_selection`, `perform_action`, and `capture_dialog`) based on how they are used in your actual application.

4. Python doesn't support direct translation of Java's package structure into Python modules.