class ElfMage:
    def __init__(self, elf_mage=None):
        super().__init__()
        if elf_mage:
            self.help_type = elf_mage.help_type
        else:
            self.help_type = None

    @property
    def help_type(self):
        return self._help_type

    @help_type.setter
    def help_type(self, value):
        self._help_type = value

    def copy(self):
        return ElfMage(self)

    def __str__(self):
        return f"Elven mage helps in {self.help_type}"
