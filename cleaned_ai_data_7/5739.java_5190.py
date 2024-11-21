class LCSSelectionEvent:
    def __init__(self, selection):
        self.selection = selection

    def __str__(self):
        return f"LSE{{{selection}}}"
