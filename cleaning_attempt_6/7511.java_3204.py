class FGVertexListingModel:
    def __init__(self, program, format_manager):
        super().__init__(program, format_manager)
        self.is_dirty = False

    def refresh(self):
        if not self.is_dirty:
            return False
        self.is_dirty = False
        if not self.program.is_closed():
            self.notify_data_changed(True)
            return True
        return False

    def domain_object_changed(self, ev):
        self.is_dirty = True

# Note: In Python, we don't have a direct equivalent of Java's "package" statement.
# Instead, you would typically put this class in its own file (e.g. `fg_vertex_listing_model.py`)
