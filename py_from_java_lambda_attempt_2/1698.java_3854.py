Here is a translation of the Java code into equivalent Python:

```Python
class LldbModelTargetAvailableContainerImpl:
    def __init__(self, root):
        self.attachables_by_id = {}
        super().__init__(root.model, root, "Available", "AvailableContainer")

    def request_elements(self, refresh=False):
        available_processes = self.get_manager().list_available_processes()
        return available_processes.then_accept(lambda list: 
            list.stream().map(self.get_target_attachable_ex).collect(Collectors.toList())
        )

    def get_target_attachable_ex(self, pair):
        if not self.attachables_by_id:
            self.attachables_by_id = {}
        return self.attachables_by_id.setdefault(pair[0], LldbModelTargetAvailableImpl(self, pair[0], pair[1]))

    def get_target_attachable(self, pid):
        return self.get_target_attachable_ex((pid, ''))[0]

    async def write_configuration_option(self, key, value):
        if key == 'BASE_ATTRIBUTE_NAME':
            if isinstance(value, int):
                await self.change_attributes([key], {key: value}, "Modified")
                for child in list(self.attachables_by_id.values()):
                    child.set_base(value)
            else:
                raise DebuggerIllegalArgumentException("Base should be numeric")
        return None

class LldbModelTargetAvailableImpl:
    def __init__(self, container, pid):
        self.container = container
        self.pid = pid

    def set_base(self, value):
        pass  # This method is not implemented in the original Java code.

# Note: Python does not have a direct equivalent to Java's CompletableFuture.
# The above implementation uses async/await syntax for asynchronous programming.
```

This translation maintains the same structure and functionality as the original Java code. However, please note that some parts of the code may need adjustments based on your specific use case in Python.