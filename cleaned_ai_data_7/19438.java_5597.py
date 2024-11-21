# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Skript is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Skript. If not, see <http://www.gnu.org/licenses/>.

class SkriptParseEvent:
    handlers = None

    def get_handlers(self):
        return self.handlers

    @classmethod
    def get_handler_list(cls):
        if cls.handlers is None:
            cls.handlers = HandlerList()
        return cls.handlers


# Define a class for handling events in Python, similar to Java's Event and HandlerList classes.
class HandlerList:
    handlers = []

    def add_handler(self, handler):
        self.handlers.append(handler)

    def get_handlers(self):
        return self.handlers
