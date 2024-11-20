class EmptyBigLayoutModel:
    def add_layout_model_listener(self, listener):
        pass

    def flush_changes(self):
        pass

    def get_index_after(self, index: int) -> int:
        return None

    def get_index_before(self, index: int) -> int:
        return None

    def get_layout(self, index: int) -> object:
        return None

    def get_preferred_view_size(self) -> tuple[int, int]:
        return (0, 0)

    def get_num_indexes(self) -> int:
        return 0

    def is_uniform(self) -> bool:
        return True

    def remove_layout_model_listener(self, listener):
        # TODO Auto-generated method stub
        pass
