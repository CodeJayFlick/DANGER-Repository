class GdbStartCommand:
    def __init__(self, manager):
        pass  # super(manager) in Java equivalent

    def get_interpreter(self):  # getInterpreter() in Java
        return "MI2"  # Interpreter.MI2 in Java

    def encode(self):  # encode method from the original code
        if self.get_interpreter() == "CLI":
            return "start"
        else:
            return "-exec-run --start"

# Usage example:

manager = None  # equivalent to GdbManagerImpl manager in Java
command = GdbStartCommand(manager)
print(command.encode())
