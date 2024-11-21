class IndexedScrollable:
    def __init__(self):
        pass

    def get_index_count(self) -> int:
        raise NotImplementedError("Method not implemented")

    def is_uniform_index(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def get_height(self, index: int) -> int:
        raise NotImplementedError("Method not implemented")

    def show_index(self, index: int, vertical_offset: int):
        raise NotImplementedError("Method not implemented")

    def get_index_after(self, index: int) -> int:
        raise NotImplementedError("Method not implemented")

    def get_index_before(self, index: int) -> int:
        raise NotImplementedError("Method not implemented")

    def scroll_line_up(self):
        raise NotImplementedError("Method not implemented")

    def scroll_line_down(self):
        raise NotImplementedError("Method not implemented")

    def scroll_page_up(self):
        raise NotImplementedError("Method not implemented")

    def scroll_page_down(self):
        raise NotImplementedError("Method not implemented")

    def add_index_scroll_listener(self, listener):
        raise NotImplementedError("Method not implemented")

    def remove_index_scroll_listener(self, listener):
        raise NotImplementedError("Method not implemented")
