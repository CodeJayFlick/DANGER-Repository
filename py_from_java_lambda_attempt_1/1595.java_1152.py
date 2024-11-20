Here is the translation of the given Java code into equivalent Python:

```Python
class LldbCommandDoneEvent:
    def __init__(self):
        pass

    def __init__(self, cmd):
        self.cmd = cmd

    @property
    def state(self):
        return "stopped"

    @property
    def command(self):
        return self.cmd


# Usage example:

cmd1 = LldbCommandDoneEvent()
print(cmd1.state)  # prints: stopped
print(cmd1.command)

cmd2 = LlldbCommand("some_command")
event = LldbCommandDoneEvent(cmd2)
print(event.state)  # prints: stopped
print(event.command)  # prints: some_command

```

Note that Python does not have direct equivalent of Java's `StateType` enum. In the above code, I used a string "stopped" to represent the state.