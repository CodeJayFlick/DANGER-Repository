class CommandInfo:
    def __init__(self):
        self.info_types = {
            "name": lambda command: [command.getName()],
            "description": lambda command: [command.getDescription()],
            "label": lambda command: [command.getLabel()],
            "usage": lambda command: [command.getUsage()],
            "aliases": lambda command: list(command.getAliases()),
            "permission": lambda command: [command.getPermission()],
            "permission_message": lambda command: [command.getPermissionMessage()],
            "plugin": lambda command: ["Bukkit" if isinstance(command, org.bukkit.command.BukkitCommand) else
                                      "Spigot" if command.getClass().getPackage().getName().startswith("org.spigot") else
                                      "Paper" if command.getClass().getPackage().getName().startswith("com.destroystokyo.paper") else None]
        }

    def get(self, event):
        commands = [Commands.getCommandMap().getCommand(command_name) for command_name in self.command_names(event)]
        return list(map(lambda x: self.info_types[self.type](x), filter(None, commands)))

    def is_single(self):
        return self.type == "aliases" or len(self.command_names) == 1

    def get_return_type(self):
        return str

    def __str__(self, event=None, debug=False):
        if not event:
            return f"the {self.type.lower().replace('_', ' ')} of command"
        else:
            return f"{event} the {self.type.lower().replace('_', ' ')} of command"

class CommandInfoExpression(Expression[str]):
    def __init__(self, expression_type=ExpressionType.SIMPLE):
        super().__init__(expression_type)

    @property
    def type(self):
        pass

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def command_names(self):
        pass

    @command_names.setter
    def command_names(self, value):
        self._command_names = value

    def init(self, exprs: list[Expression], matched_pattern: int, is_delayed: Kleenean, parse_result: ParseResult) -> bool:
        if len(exprs) > 0 and isinstance(exprs[0], Expression[str]):
            self.command_names = [exprs[0]]
        else:
            raise ValueError("Invalid command name")
        return True

    def __call__(self):
        pass
