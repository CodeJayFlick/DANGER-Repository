class ProgramLocationPreviewTableModel:
    def __init__(self, model_name: str, sp: object, prog: object, monitor: object):
        pass  # equivalent to super().__init__()

    @property
    def column_descriptors(self) -> list[dict]:
        return [
            {"name": "Address", "visible": True},
            {"name": "Label", "visible": True},
            {"name": "Namespace", "visible": True},
            {"name": "Preview", "visible": True}
        ]

    def get_address(self, row: int) -> object:
        loc = self.get_row_object(row)
        return loc.address

class ProgramLocation:
    def __init__(self):
        pass  # equivalent to super().__init__()

    @property
    def address(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")

def main():
    sp = None  # ServiceProvider
    prog = None  # Program
    monitor = None  # TaskMonitor

    model = ProgramLocationPreviewTableModel("Model Name", sp, prog, monitor)
