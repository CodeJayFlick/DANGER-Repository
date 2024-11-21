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
