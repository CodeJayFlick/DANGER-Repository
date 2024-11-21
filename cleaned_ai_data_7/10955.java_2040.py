class NonExistentIMGFileInvalidLink:
    MESSAGE = "Unable to locate image file"

    def __init__(self, img):
        super().__init__(img, self.MESSAGE)
