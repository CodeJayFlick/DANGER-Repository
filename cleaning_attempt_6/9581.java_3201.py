class LayoutModel:
    def __init__(self):
        pass

    def is_uniform(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def preferred_view_size(self) -> tuple[int, int]:
        raise NotImplementedError("Subclasses must implement this property")

    @property
    def num_indexes(self) -> int:
        raise NotImplementedError("Subclasses must implement this property")

    def index_after(self, index: int) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def index_before(self, index: int) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_layout(self, index: int) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def iterator(self) -> 'LayoutModelIterator':
        return LayoutModelIterator(self)

    def iterator(self, start_index: int) -> 'LayoutModelIterator':
        return LayoutModelIterator(self, start_index)

    def add_layout_model_listener(self, listener):
        raise NotImplementedError("Subclasses must implement this method")

    def remove_layout_model_listener(self, listener):
        raise NotImplementedError("Subclasses must implement this method")

    def flush_changes(self):
        pass
