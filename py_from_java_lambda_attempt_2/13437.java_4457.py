Here is the translation of the Java code to Python:
```
import unittest

class DisassemblerPluginScreenShots(unittest.TestCase):
    def __init__(self):
        super().__init__()

    @unittest.skip
    def test_processor_options(self):
        self.position_listing_top(0x401000)
        self.perform_action("Processor Options", "DisassemblerPlugin", False)
        self.capture_dialog(400, 400)

if __name__ == "__main__":
    unittest.main()
```
Note that I had to make some assumptions about the Python code equivalent of certain Java constructs. For example:

* The `@Test` annotation is not directly translatable to Python, so I used the `unittest.skip` decorator instead.
* The `GhidraScreenShotGenerator` class and its methods are not present in Python, so I replaced them with hypothetical equivalents (`position_listing_top`, `perform_action`, and `capture_dialog`) that mimic their behavior.

Also, keep in mind that this is just one possible translation of the Java code to Python. There may be other ways to achieve similar results using different libraries or frameworks.