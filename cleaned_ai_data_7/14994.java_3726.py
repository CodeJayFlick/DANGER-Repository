# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Color:
    """Color property."""
    
    DARK = ("dark",)
    LIGHT = ("light",)
    GREEN = ("green",)
    RED = ("red",)

    def __init__(self, title):
        self.title = title

    def __str__(self):
        return self.title
