# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import datetime

class DefaultClasses:
    OBJECT = None
    NUMBER = None
    LONG = None
    BOOLEAN = None
    STRING = None
    
    WORLD = None
    LOCATION = None
    VECTOR = None
    
    COLOR = None
    DATE = None
    TIMESPAN = None

    def __init__(self):
        self.OBJECT = type('Object', (), {})
        self.NUMBER = int
        self.LONG = long
        self.BOOLEAN = bool
        self.STRING = str
        
        from world import World, Location, Vector
        self.WORLD = World
        self.LOCATION = Location
        self.VECTOR = Vector

        from color import Color
        self.COLOR = Color

        from date_time import Date, Timespan
        self.DATE = datetime.date
        self.TIMESPAN = datetime.timedelta

    def getClassInfo(self, tClass):
        if not isinstance(tClass, type):
            raise TypeError("tClass must be a class")
        
        return tClass
