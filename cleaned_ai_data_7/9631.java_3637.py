import re

class CharacterTermSplitter:
    def __init__(self, delimiter):
        self.delimiter = str(delimiter)

    def split(self, string):
        return re.split(str(self.delimiter), string)
