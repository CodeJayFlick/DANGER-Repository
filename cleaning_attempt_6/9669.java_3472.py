class UniformViewToIndexMapper:
    def __init__(self, scrollable):
        self.scrollable = scrollable
        self.compute_heights()

    def compute_heights(self):
        layout_height = self.scrollable.get_height(BigInteger(0))
        if layout_height < 1:
            layout_height = 1
        view_height = self.scrollable.index_count * layout_height

    @property
    def view_height(self):
        return self.view_height

    def get_index(self, value: int) -> 'BigInteger':
        index = value // self.layout_height
        return BigInteger(str(index))

    def get_vertical_offset(self, value: int) -> int:
        index = value // self.layout_height
        return (index * self.layout_height) - value

    @property
    def visible_view_height(self):
        pass  # no-op

    def get_scroll_value(self, start_index: 'BigInteger', end_index: 'BigInteger', start_y: int, end_y: int) -> int:
        start_int = start_index.value()
        return start_int * self.layout_height - start_y

    @property
    def index_model_data_changed(self):
        pass  # no-op
