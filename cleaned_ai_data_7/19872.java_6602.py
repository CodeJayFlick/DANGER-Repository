import os
from collections import defaultdict

class SkriptCommand:
    CONFIG_NODE = "skript command"

    def __init__(self):
        self.skript_command_help = CommandHelp("<gray>/<gold>skript", SkriptColor.LIGHT_CYAN, self.CONFIG_NODE + ".help")
        # ... (rest of the class definition)

    @staticmethod
    def reloading(sender, what, *args):
        if not args:
            what = Language.get(self.CONFIG_NODE + "." + what)
        else:
            what = PluralizingArgsMessage.format(Language.format(self.CONFIG_NODE + "." + what, *args))
        Skript.info(sender, fix_capitalization(what))

    @staticmethod
    def reloaded(sender, log_handler, what, *args):
        if not args:
            what = Language.get(self.CONFIG_NODE + "." + what)
        else:
            what = PluralizingArgsMessage.format(Language.format(self.CONFIG_NODE + "." + what, *args))
        if log_handler.num_errors() == 0:
            Skript.info(sender, fix_capitalization(PluralizingArgsMessage.format(m_reloaded.toString(what))))
        else:
            Skript.error(sender, fix_capitalization(PluralizingArgsMessage.format(m_reload_error.toString(what, log_handler.num_errors()))))

    @staticmethod
    def info(sender, what, *args):
        if not args:
            what = Language.get(self.CONFIG_NODE + "." + what)
        else:
            what = PluralizingArgsMessage.format(Language.format(self.CONFIG_NODE + "." + what, *args))
        Skript.info(sender, fix_capitalization(what))

    @staticmethod
    def error(sender, what, *args):
        if not args:
            what = Language.get(self.CONFIG_NODE + "." + what)
        else:
            what = PluralizingArgsMessage.format(Language.format(self.CONFIG_NODE + "." + what, *args))
        Skript.error(sender, fix_capitalization(what))

    def on_command(self, sender, command, label, args):
        if not (sender and command and label and args):
            raise ValueError()
        if self.skript_command_help.test(sender, args) is False:
            return True
        try:
            with RedirectingLogHandler(sender, "") as log_handler:
                # ... (rest of the method definition)
