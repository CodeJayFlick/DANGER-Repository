class IndexScrollListener:
    def on_index_range_changed(self, start: int, end: int, y_start: int, y_end: int):
        pass  # implement this method in your subclass

    def on_index_model_changed(self) -> None:
        pass  # implement this method in your subclass

    def on_index_model_data_changed(self, start: int, end: int) -> None:
        pass  # implement this method in your subclass
