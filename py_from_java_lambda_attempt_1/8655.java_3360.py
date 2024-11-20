Here is the translation of the given Java code into Python:

```Python
class NextDiffCommand:
    def __init__(self, plugin):
        self.plugin = plugin

    def apply_to(self, obj, monitor):
        monitor.set_message("NextDiffTask starting...")
        self.plugin.next_diff()
        return True


# Example usage:
plugin = ProgramDiffPlugin()  # Replace with your actual class
command = NextDiffCommand(plugin)
domain_object = DomainObject()  # Replace with your actual object
task_monitor = TaskMonitor()

result = command.apply_to(domain_object, task_monitor)

print(result)  # This should print: True
```

Please note that this is a direct translation of the Java code into Python. The equivalent classes and methods in Python are:

- `class` instead of `public class`
- `def __init__(self, plugin):` for constructor (Java's no-arg constructor is not necessary)
- `monitor.set_message("NextDiffTask starting...")` to set a message
- `return True` at the end of the method

Also note that Python does not have direct equivalents of Java classes like DomainObject and TaskMonitor. You would need to replace these with actual objects or data structures in your Python code, depending on how you plan to use them.