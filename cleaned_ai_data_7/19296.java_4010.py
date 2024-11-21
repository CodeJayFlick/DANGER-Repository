# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

class InvalidNode:
    def __init__(self, value, comment, parent, line_num):
        super().__init__(value, comment, parent, line_num)
        self.config.errors += 1

# class SectionNode: # This is not defined in the original code
