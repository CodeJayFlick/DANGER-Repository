class MissingFileInvalidLink(Exception):
    def __init__(self, href):
        super().__init__("Unable to locate reference file")
        self.href = href
