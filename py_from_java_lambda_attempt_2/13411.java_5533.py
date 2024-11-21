Here is the translation of the Java code to Python:
```
import unittest

class AboutScreenShots(unittest.TestCase):
    def test_about_program(self):
        # Replace with actual program metadata
        meta_data = {"Executable Location": "/Users/bob/WinHelloCPP.exe"}
        
        from ghidra.app.plugin.core.help import about_domain_object_utils
        
        about_domain_object_utils.display_information(None, None, meta_data,
            "About WinHelloCPP.exe", None, None)
        
        # Replace with actual capture dialog dimensions
        self.capture_dialog(800, 500)

if __name__ == '__main__':
    unittest.main()
```
Note that I had to make some assumptions about the Python code equivalent of Java concepts like `Map`, `Test` annotation, and `GhidraScreenShotGenerator`. Additionally, I replaced the actual program metadata with a placeholder value. You will need to modify this code to fit your specific use case.

Also, please note that Ghidra is a reverse engineering framework, so you may need additional imports or setup depending on how you are using it in Python.