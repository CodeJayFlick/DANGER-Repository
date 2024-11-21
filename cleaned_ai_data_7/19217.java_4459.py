# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

class ScriptCommandEvent:
    def __init__(self, command, sender):
        self.skript_command = command
        super().__init__(sender, command.label, None)

    @property
    def skript_command(self):
        return self._skript_command

    @property
    def cooldown_cancelled(self):
        return self._cooldown_cancelled

    @cooldown_cancelled.setter
    def cooldown_cancelled(self, value):
        self._cooldown_cancelled = value

class HandlerList:
    pass

# Bukkit stuff (not implemented in Python)
handlers = HandlerList()

def get_handlers(self):
    return handlers

get_handler_list = staticmethod(get_handlers)

if __name__ == "__main__":
    # Example usage
    command = ScriptCommand("example", "Example Command")
    sender = CommandSender()  # Not a real class, just an example
    event = ScriptCommandEvent(command, sender)
    print(event.skript_command.label)  # prints "Example Command"
