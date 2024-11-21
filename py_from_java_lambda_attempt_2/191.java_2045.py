Here is the translation of the Java code into Python:

```Python
class DebuggerModelNode:
    def __init__(self, model: 'DebuggerObjectModel', provider: 'DebuggerTargetsProvider'):
        self.model = model
        self.provider = provider
        self.name = f"{model.__class__.__name__}@{hex(id(model))}"

        self.model.add_model_listener(self)

    @property
    def display_text(self):
        return self.model.get_brief()

    @property
    def name_(self):
        return self.name

    @property
    def is_leaf(self):
        return True

    def get_debugger_model(self) -> 'DebuggerObjectModel':
        return self.model

    def model_state_changed(self):
        self.provider.update_tree(False, None)
```

Note that I used Python's type hinting to indicate the types of variables and method parameters.