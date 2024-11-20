Here is the translation of the Java code to Python:
```
import unittest

class ProgramTreePluginScreenShots(unittest.TestCase):
    def __init__(self):
        super().__init__()

    @unittest.skip
    def test_view_manager(self):
        remove_flow_arrows()
        close_provider(DataTypesProvider)
        set_divider_percentage(0.25, DataTypesProvider, CodeViewerProvider)
        capture_window(tool.get_tool_frame(), 1000, 600)

if __name__ == '__main__':
    unittest.main()
```
Note that I had to make some assumptions about the Python code equivalents of certain Java constructs (e.g., `@Test` annotation is equivalent to a test method in Python), and also removed any imports that were not directly related to the provided code.