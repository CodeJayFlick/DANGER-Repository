class ElfWarlord:
    def __init__(self, help_type):
        self.help_type = help_type

    def copy(self):
        return ElfWarlord(self)

    def __str__(self):
        return f"Elven warlord helps in {self.help_type}"
