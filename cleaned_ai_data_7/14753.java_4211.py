class ElfBeast:
    def __init__(self, elf_beast=None):
        if elf_beast:
            super().__init__()
            self.help_type = elf_beast.help_type
        else:
            pass  # Initialize with default values

    @property
    def help_type(self):
        return self._help_type

    @help_type.setter
    def help_type(self, value):
        self._help_type = value

    def copy(self):
        return ElfBeast(elf_beast=self)

    def __str__(self):
        return f"Elven eagle helps in {self.help_type}"
