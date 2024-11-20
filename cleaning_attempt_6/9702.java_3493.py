class SearchLocation:
    def __init__(self, start_index_inclusive: int, end_index_inclusive: int, search_text: str, forward_direction: bool):
        self.start_index_inclusive = start_index_inclusive
        self.end_index_inclusive = end_index_inclusive
        self.search_text = search_text
        self.forward_direction = forward_direction

    def get_cursor_position(self) -> 'CursorPosition':
        return CursorPosition(self.start_index_inclusive)

    @property
    def search_text(self) -> str:
        return self.search_text

    @property
    def end_index_inclusive(self) -> int:
        return self.end_index_inclusive

    @property
    def start_index_inclusive(self) -> int:
        return self.start_index_inclusive

    @property
    def match_length(self) -> int:
        return self.end_index_inclusive - self.start_index_inclusive + 1

    def is_forward_direction(self) -> bool:
        return self.forward_direction

    def __str__(self):
        return f"{self.search_text} [{self.fields_to_string()}]"

    def fields_to_string(self) -> str:
        return f"{self.start_index_inclusive}, end={self.end_index_inclusive}"
