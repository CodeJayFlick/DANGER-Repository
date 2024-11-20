# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Nourishment:
    """Nourishment enumeration."""
    
    SATURATED = ("saturated",)
    HUNGRY = ("hungry",)
    STARVING = ("starving",)

    def __init__(self, title):
        self.title = title

    def __str__(self):
        return self.title
