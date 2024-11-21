# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class FishingBoatAdapter:
    """ Adapter class. Adapts the interface of the device (FishingBoat)
        into RowingBoat interface expected by the client (Captain). """

    def __init__(self):
        self.boat = FishingBoat()

    def row(self):
        self.boat.sail()
