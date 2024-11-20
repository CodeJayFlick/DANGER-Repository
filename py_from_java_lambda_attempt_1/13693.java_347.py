Here's the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class ElfArmy:
    """Elf Army."""
    
    DESCRIPTION = "This is the elven army!"

    def get_description(self):
        return self.DESCRIPTION


if __name__ == "__main__":
    print(ElfArmy().get_description())
```

Please note that Python does not have a direct equivalent to Java's `package` statement. The above code defines a class named ElfArmy in the global namespace.