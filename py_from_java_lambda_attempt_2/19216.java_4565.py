Here is the translation of the Java code into Python:

```Python
class ScriptCommand:
    def __init__(self, script: str, name: str, pattern: str, arguments: list, description: str, usage: str, aliases: list, permission: str = '', cooldown_message: str = None):
        self.name = name
        self.label = f"{name.lower()}"
        self.permission = permission
        if not permission:
            self.permission_message = VariableString("commands.no permission message")
        else:
            self.permission_message = VariableString(permission)
        
        self.cooldown = cooldown_message
        self.usage = usage
        
        # remove aliases that are the same as the command
        for alias in aliases[:]:
            if label.lower() == alias.lower():
                aliases.remove(alias)

    def on_command(self, sender: CommandSender, command: str, label: str, args: list):
        if not (sender and label and args):
            return False
        
        self.execute(sender, label, ' '.join(args))
        
        return True

    def execute(self, sender: CommandSender, label: str, rest: str):
        if isinstance(sender, Player) and (self.executable_by & 0x1 == 0):
            sender.sendMessage(f"{m_executable_by_console}")
            return False
        elif not isinstance(sender, Player) and (self.executable_by & 0x2 == 0):
            sender.sendMessage(f"{m_executable_by_players}")
            return False
        
        event = ScriptCommandEvent(self, sender)
        
        if self.permission and not sender.has_permission(self.permission):
            components = permission_message.get_components(event)
            if isinstance(sender, Player):
                player = sender
                for component in components:
                    player.spigot().sendMessage(BungeeConverter.convert(component))
            else:
                sender.sendMessage(permission_message.get_single(event))
            
            return False
        
        cooldown_check: 
        if isinstance(sender, Player) and self.cooldown is not None:
            uuid = sender.unique_id
            
            # Cooldown bypass
            if self.cooldown_bypass and player.has_permission(self.cooldown_bypass):
                set_last_usage(uuid, event, None)
                break cooldown_check
        
            if get_last_usage(uuid, event) is not None:
                if get_remaining_milliseconds(uuid, event) <= 0:
                    if not SkriptConfig.keep_last_usage_dates.value():
                        set_last_usage(uuid, event, None)
                    else:
                        msg = self.cooldown_message.get_single(event)
                        if msg:
                            sender.sendMessage(msg)
                    
                    return False
        
        execute2(event, sender, label, rest)
        
        if isinstance(sender, Player) and not event.is_cooldown_cancelled():
            set_last_usage(uuid, event, Date())
        
    def send_help(self, sender: CommandSender):
        if self.description:
            sender.sendMessage(self.description)
        sender.sendMessage(f"Usage: {self.usage}")

    @property
    def arguments(self):
        return self._arguments

    @property
    def pattern(self):
        return self._pattern

    # ... other methods ...
```

Please note that Python does not support direct translation of Java code. It is a different language with its own syntax and structure, so you will need to rewrite the logic in Python.