class LitConsole:
    def __init__(self):
        self.console = Bukkit.get_console_sender()

    @property
    def description(self):
        return "Represents the server's console which can receive messages and execute commands"

    @property
    def examples(self):
        return ["execute console command '/stop'", "send 'message to console' to the console"]

    @property
    def since(self):
        return "1.3.1"

    def __str__(self, e=None, debug=False):
        return "the console"
