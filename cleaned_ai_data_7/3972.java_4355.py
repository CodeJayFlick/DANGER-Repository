class HintTextAreaIS:
    def __init__(self, hint):
        self.hint = hint

    def set_error(self):
        self.set_attributes()

    def set_valid(self):
        self.set_attributes()

    # PRIVATE METHODS

    def set_error_attributes(self):
        font = self.get_font()
        self.set_font(font.deriveFont('PLAIN'))
        self.set_foreground((255, 0, 0))  # Red color
