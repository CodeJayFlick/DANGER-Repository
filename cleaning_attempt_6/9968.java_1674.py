import tkinter as tk

class EndOfLineAction:
    KEY_STROKE = "end"
    ACTION_NAME = "caret-end-line"

    def __init__(self):
        pass

    @staticmethod
    def error(component):
        # equivalent to UIManager.getLookAndFeel().provideErrorFeedback(component)
        print("Error:", component)

    def actionPerformed(self, e):
        if isinstance(e.widget, tk.Text):
            try:
                dot = e.widget.index("end-1c")
                end_position = e.widget.index(f"insert {dot} lineend")
                e.widget.see(end_position)
                e.widget.mark_set(0, end_position)
            except Exception as bl:
                EndOfLineAction.error(e.widget)

if __name__ == "__main__":
    pass
