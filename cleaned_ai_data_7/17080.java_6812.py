class LoadEmptyFileException(Exception):
    def __init__(self):
        super().__init__("Cannot load an empty file")
