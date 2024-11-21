import unittest
from ghidra_screenshot import GhidraScreenShotGenerator


class FunctionWindowPluginScreenShots(GhidraScreenShotGenerator):
    def __init__(self):
        super().__init__()

    @unittest.skip("Test not implemented")
    def test_function_window(self):
        self.show_provider(FunctionWindowProvider)
        self.set_column_sizes()
        self.capture_isolated_provider(FunctionWindowProvider, 700, 300)

    def set_column_sizes(self):
        provider = self.get_provider(FunctionWindowProvider)
        table = getattr(provider, 'functionTable')
        column_model = table.columnModel
        for i in range(column_model.getColumnCount()):
            column = column_model.getColumn(i)
            header_value = column.getHeaderValue()
            if str(header_value) == "Name":
                column.setPreferredWidth(85)
            elif str(header_value) == "Location":
                column.setPreferredWidth(70)
            elif str(header_value) == "Function Signature":
                column.setPreferredWidth(400)
            elif str(header_value) == "Function Size":
                column.setPreferredWidth(25)


if __name__ == "__main__":
    unittest.main()
