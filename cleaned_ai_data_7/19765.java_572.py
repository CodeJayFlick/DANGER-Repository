# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from typing import Optional

class RegionExpression:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Region"

    @property
    def description(self):
        return ["The region involved in an event.",
                "This expression requires a supported regions plugin to be installed."]

    @property
    def examples(self):
        return ["on region enter:",
                "  region is {forbidden region}",
                "  cancel the event"]

    @property
    def since(self):
        return "2.1"

def register_expression():
    pass

# Register this expression with Skript.
register_expression()

if __name__ == "__main__":
    print("Region Expression")
