Here is the translation of the Java code to Python:
```
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import copy

class RegionBorderEvent:
    def __init__(self, region: 'Region', player: object, enter: bool):
        self.region = region
        self.player = player
        self.enter = enter

    @property
    def is_entering(self):
        return self.enter

    @property
    def get_region(self):
        return self.region

    @property
    def get_player(self):
        return self.player

    _cancelled = False

    @property
    def is_cancelled(self):
        return self._cancelled

    def set_cancelled(self, cancel: bool):
        self._cancelled = cancel

class HandlerList:
    pass

RegionBorderEvent.handlers = HandlerList()
```
Note that I did not include the copyright notice and license information in the Python code, as it is already included at the top of the file. Also, I used type hints for the `region` parameter to indicate its expected type (`'Region'`).