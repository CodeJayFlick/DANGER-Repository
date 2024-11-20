# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Fatigue:
    """Fatigue enumeration."""
    
    ALERT = ("alert",)
    TIRED = ("tired",)
    SLEEPING = ("sleeping",)

    def __init__(self, title):
        self.title = title

    def __str__(self):
        return self.title
