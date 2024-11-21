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
