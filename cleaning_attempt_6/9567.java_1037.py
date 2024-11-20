class EmptyLayoutBackgroundColorManager:
    def __init__(self, background: tuple):
        self.background = color(*background)

    def get_field_background_color_manager(self, field_num: int) -> 'EmptyFieldBackgroundColorManager':
        return EmptyFieldBackgroundColorManager.EMPTY_INSTANCE

    def get_background_color(self) -> tuple:
        return self.background

    def get_padding_color(self, gap: int) -> None:
        pass  # equivalent to returning null in Java

    def get_background_color_for_location(self, location: 'FieldLocation') -> tuple:
        return self.background
