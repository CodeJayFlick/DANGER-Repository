class DecompilerLocationMemento:
    def __init__(self, program, location, viewer_position):
        self.program = program
        self.location = location
        self.viewer_position = viewer_position

    @classmethod
    def from_save_state(cls, save_state, programs):
        memento = cls(None, None, None)
        index = save_state.get("INDEX", 0)
        x_offset = save_state.get("X_OFFSET", 0)
        y_offset = save_state.get("Y_OFFSET", 0)
        viewer_position = {"index": index, "x_offset": x_offset, "y_offset": y_offset}
        return memento

    def get_viewer_position(self):
        return self.viewer_position


class ViewerPosition:
    def __init__(self, index, x_offset, y_offset):
        self.index = index
        self.x_offset = x_offset
        self.y_offset = y_offset

    @property
    def index_as_int(self):
        return int(self.index)

