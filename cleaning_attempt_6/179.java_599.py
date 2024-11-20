class DebuggerAvailableRegistersActionContext:
    def __init__(self, selection):
        self.selection = selection

    @property
    def selection(self):
        return self._selection

    def get_selection(self):
        return self._selection


# Example usage:
if __name__ == "__main__":
    class AvailableRegisterRow:  # Note: This is not a built-in Python type, you may need to define it elsewhere in your code
        pass

    selection = [AvailableRegisterRow(), AvailableRegisterRow()]
    action_context = DebuggerAvailableRegistersActionContext(selection)
    print(action_context.selection)  # prints the selected registers
