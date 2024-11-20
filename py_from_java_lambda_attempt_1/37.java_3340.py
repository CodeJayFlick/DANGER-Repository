Here is the translation of the given Java code into equivalent Python:

```Python
class AutoReadMemorySpec:
    def __init__(self):
        self.specs_by_name = {}
        self.class_listener = lambda event: self.classes_changed(event)

    @staticmethod
    def private():
        instance = AutoReadMemorySpec()
        ClassSearcher.add_change_listener(instance.class_listener)
        return instance

    private_instance = private()

    class ConfigFieldCodec:
        def read(self, state, name, current):
            spec_name = state.get_string(name, None)
            return self.from_config_name(spec_name)

        def write(self, state, name, value):
            state.put_string(name, value.config_name())

    @staticmethod
    def from_config_name(name):
        with lock(private_instance.specs_by_name):
            return private_instance.specs_by_name.get(name)

    @classmethod
    def all_specs(cls):
        with lock(private_instance.specs_by_name):
            return dict.copy(private_instance.specs_by_name)

    def config_name(self):
        pass

    def menu_name(self):
        pass

    def menu_icon(self):
        pass

    def read_memory(self, tool, coordinates, visible_addresses):
        # Note: This method should perform all error handling. The returned future is for follow-up purposes only.
        return CompletableFuture.runnable(lambda: None)
```

Please note that this translation does not include the `CompletableFuture` class as it's a Java-specific class and Python has its own equivalent classes like `concurrent.futures.Future`. Also, some methods are left without implementation (like `config_name`, `menu_name`, `menu_icon`) because they were missing in the original code.