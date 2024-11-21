Here is a translation of the Java code into equivalent Python code:

```Python
class SourceTagsPanel:
    def __init__(self, provider, tool, title):
        self.provider = provider
        self.tool = tool
        self.title = title

    # PUBLIC METHODS

    def add_selected_tags(self):
        if not hasattr(self, 'function'):
            return

        selected_tags = self.get_selected_tags()
        for tag in selected_tags:
            if isinstance(tag, InMemoryFunctionTag):  # Assuming this is a custom class
                cmd = CreateFunctionTagCmd(tag.name, tag.comment)
                self.tool.execute(cmd)

            cmd = AddFunctionTagCmd(tag.name, self.function.entry_point())
            self.tool.execute(cmd)

    def refresh(self, new_function):
        if not hasattr(self, 'model'):
            return

        self.model.clear()
        self.function = new_function
        table.set_function(new_function)
        self.model.reload()

    def background_load_tags(self):
        return self.provider.background_load_tags()

    def is_selection_enabled(self):
        selected_tags = self.get_selected_tags()
        assigned_tags = self.get_assigned_tags(self.function)

        if set(assigned_tags).issuperset(selected_tags):
            return False

        return True
```

Please note that this translation assumes the following:

- The `InMemoryFunctionTag` class is a custom Python class.
- There are equivalent classes for `AddFunctionTagCmd`, `CreateFunctionTagCmd`, and others, which you would need to implement in your own code.