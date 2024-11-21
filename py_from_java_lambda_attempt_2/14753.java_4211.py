Here is the translation of the Java code to Python:

```Python
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
```

Note that Python does not have direct equivalent of Java's `@EqualsAndHashCode` and `@RequiredArgsConstructor`. In the above code, I used Python's property decorator to create a getter/setter for the `help_type` attribute.