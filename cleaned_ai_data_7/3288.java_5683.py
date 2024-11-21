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

