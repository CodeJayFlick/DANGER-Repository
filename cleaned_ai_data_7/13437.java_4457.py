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
