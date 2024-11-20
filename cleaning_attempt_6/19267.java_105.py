class IsSkriptCommand:
    def __init__(self):
        self.name = "Is a Skript command"
        self.description = "Checks whether a command/string is a custom Skript command."
        self.examples = [
            {"Example 1": ["# Example 1", "on command:", "\tcommand is a skript command", "", "# Example 2", "\"sometext\" is a skript command"]},
        ]
        self.since = "2.6"

    def check(self, cmd):
        return hasattr(cmd, 'skript_command')

# Register the class
import ch.njol.skript

ch.njol.skript.register(IsSkriptCommand)
