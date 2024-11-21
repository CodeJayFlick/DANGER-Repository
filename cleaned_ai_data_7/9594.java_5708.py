class BackgroundColorModel:
    def get_background_color(self, index: int) -> tuple:
        # Note: BigInteger in Java corresponds to int in Python
        return (0, 0, 0, 255)  # Replace with actual implementation

    def get_default_background_color(self) -> tuple:
        return self.get_background_color(0)

    def set_default_background_color(self, color: tuple):
        pass  # Replace with actual implementation
