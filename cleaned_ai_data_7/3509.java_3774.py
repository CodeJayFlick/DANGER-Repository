class CodeViewerLocationMemento:
    def __init__(self, program, location, cursor_offset):
        self.program = program
        self.location = location
        self.cursor_offset = cursor_offset

    @classmethod
    def from_save_state(cls, save_state, programs):
        memento = cls(None, None, 0)
        super().__init__(save_state, programs)
        memento.cursor_offset = save_state.get("CURSOR_OFFSET", 0)
        return memento

    def get_cursor_offset(self):
        return self.cursor_offset

    def save_state(self, save_state):
        super().save_state(save_state)
        save_state["CURSOR_ OFFSET"] = self.cursor_offset
