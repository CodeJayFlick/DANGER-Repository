Here is the translation of the given Java code into Python:

```Python
class ProgramActivatedPluginEvent:
    NAME = "Program Activated"

    def __init__(self, source: str, active_program):
        super().__init__(source, self.NAME)
        self.new_program_ref = weakref.ref(active_program)

    @property
    def active_program(self) -> 'Program':
        return self.new_program_ref()

class Program:
    pass

# Example usage:

def main():
    program1 = Program()
    event1 = ProgramActivatedPluginEvent("Source", program1)
    
    print(event1.active_program)  # prints: <__main__.Program object at 0x7f9e5c6a3b50>

if __name__ == "__main__":
    main()

```

Note that Python does not have direct equivalent of Java's `WeakReference` class. However, the `weakref.ref()` function in Python can be used to achieve similar functionality.

Also note that this translation is based on my understanding of your requirements and may need further adjustments depending on how you plan to use these classes in your actual program.