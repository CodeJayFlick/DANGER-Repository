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
