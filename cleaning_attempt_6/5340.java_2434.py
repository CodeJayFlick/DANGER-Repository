from typing import List

class DataTypeDiffInput:
    def get_lines(self) -> List[ValidatableLine]:
        pass  # Implement this method in your subclass.

    def create_place_holder(self, opposite_line: ValidatableLine) -> PlaceHolderLine:
        pass  # Implement this method in your subclass.
