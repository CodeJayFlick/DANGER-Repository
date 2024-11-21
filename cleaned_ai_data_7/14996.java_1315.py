# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Movement:
    """Movement property."""
    
    WALKING = ("walking",)
    SWIMMING = ("swimming",)
    FLYING = ("flying",)

    def __init__(self, title):
        self.title = title
    
    def __str__(self):
        return self.title
