class AllCommands:
    def __init__(self):
        self.script_commands_only = None

    @property
    def script_commands_only(self):
        return self._script_commands_only

    @script_commands_only.setter
    def script_commands_only(self, value):
        self._script_commands_only = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if parse_result.mark == 1:
            self.script_commands_only = True
        return True

    def get(self, e=None):
        if self.script_commands_only:
            return [command.get_label() for command in Commands().get_script_commands()]
        else:
            try:
                commands = Commands().get_command_map().values()
                return [command.get_label() for command in commands]
            except AttributeError:
                return None

    def is_single(self):
        return False

    @property
    def return_type(self):
        return str

    def __str__(self, e=None, debug=False):
        if self.script_commands_only:
            return "script commands"
        else:
            return f"all {''}commands"

# Usage example:

class Commands:
    def get_script_commands(self):
        # Your implementation here
        pass

    def get_command_map(self):
        # Your implementation here
        pass

    def __init__(self):
        self.script_commands = []
        self.command_map = {}

    @property
    def script_commands(self):
        return self._script_commands

    @script_commands.setter
    def script_commands(self, value):
        self._script_commands = value

    @property
    def command_map(self):
        return self._command_map

    @command_map.setter
    def command_map(self, value):
        self._command_map = value


# Example usage:
all_commands = AllCommands()
commands = Commands()

print(all_commands.get())  # prints all commands or script commands based on the input
