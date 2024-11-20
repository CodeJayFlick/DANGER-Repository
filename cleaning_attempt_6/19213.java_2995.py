class Commands:
    m_too_many_arguments = "commands.to many arguments"
    m_internal_error = "commands.internal error"
    m_correct_usage = "commands.correct usage"

    commands = {}

    @staticmethod
    def init():
        try:
            if isinstance(Bukkit.get_plugin_manager(), SimplePluginManager):
                command_map_field = SimplePluginManager().__dict__["commandMap"]
                command_map_field.set("accessible", True)
                Commands.command_map = command_map_field.get()
                
                known_commands_field = CommandMap().__dict__["knownCommands"]
                Commands.cm_known_commands = known_commands_field
                
        except (SecurityException, Exception):
            Skript.error("Please disable the security manager")
            Commands.command_map = None

    @staticmethod
    def load_command(node):
        key = node.get_key()
        
        if not key:
            return None
        
        s = ScriptLoader.replace_options(key)
        
        level = 0
        for i in range(len(s)):
            if s[i] == '[':
                level += 1
            elif s[i] == ']':
                if level == 0:
                    Skript.error("Invalid placement of [optional brackets]")
                    return None
                level -= 1
        
        if level > 0:
            Skript.error("Invalid amount of [optional brackets]")
            return None

        m = command_pattern.match(s)
        
        if not m:
            return None
        
        command = s.lower()
        existing_command = Commands.commands.get(command)
        if existing_command and existing_command.label == command:
            f = existing_command.script
            Skript.error("A command with the name /" + existing_command.name + " is already defined" + (f is None and "" or " in " + str(f)))
            return None

    @staticmethod
    def skript_command_exists(command):
        c = Commands.commands.get(command)
        if c:
            return True
        else:
            return False

    @staticmethod
    def register_command(command):
        existing_command = Commands.commands.get(command.label)
        
        if existing_command and existing_command.label == command.label:
            f = existing_command.script
            Skript.error("A command with the name /" + existing_command.name + " is already defined" + (f is None and "" or " in " + str(f)))
            return
        
        if Commands.command_map:
            cm_known_commands = Commands.cm_known_commands
            cm_aliases = Commands.cm_aliases
            
            for alias in command.active_aliases:
                Commands.commands[alias.lower()] = command

    @staticmethod
    def unregister_commands(script):
        num_commands = 0
        commands_iter = iter(Commands.commands.values())
        
        while True:
            try:
                c = next(commands_iter)
            except StopIteration:
                break
            
            if script == c.script:
                num_commands += 1
                c.unregister_help()
                
    @staticmethod
    def register_listeners():
        if not registered_listeners:
            Bukkit.get_plugin_manager().register_events(command_listener, Skript.instance())
            
            post13_listener = post1_3chat_listener
            
            if post13_listener is not None:
                Bukkit.get_plugin_manager().register_events(post13_listener, Skript.instance())
            else:
                pre13_listener = pre1_3chat_listener
                Bukkit.get_plugin_manager().register_events(pre13_listener, Skript.instance())

    @staticmethod
    def clear_commands():
        if Commands.command_map is not None:
            cm_known_commands = Commands.cm_known_commands
            
            for c in list(Commands.commands.values()):
                c.unregister_help()
                
        Commands.commands.clear()

class CommandAliasHelpTopic(HelpTopic):
    alias_for: str
    help_map: HelpMap

    def __init__(self, alias, alias_for, help_map):
        self.alias_for = alias_for if not alias.startswith('/') else '/' + alias_for
        self.help_map = help_map
        
        name = alias if not alias.startswith('/') else '/' + alias
        super().__init__(name)
        
        short_text = f"{ChatColor.YELLOW}Alias for {ChatColor.WHITE}{self.alias_for}"
        
    def get_full_text(self, command_sender):
        sb = StringBuilder(short_text)

        help_topic_alias_for = self.help_map.get_help_topic(self.alias_for)
        
        if help_topic_alias_for is not None:
            sb.append('\n')
            sb.append(help_topic_alias_for.get_full_text(command_sender))
            
        return str(sb.toString())

    def can_see(self, command_sender):
        if amended_permission is None:
            alias_for_topic = self.help_map.get_help_topic(self.alias_for)
            
            if alias_for_topic is not None:
                return alias_for_topic.can_see(command_sender)
            else:
                return False
        assert amended_permission is not None
        return command_sender.has_permission(amended_permission)

command_pattern = re.compile(r'(?i)^command/?(\\S+)?(\\s+(.+?)?')
