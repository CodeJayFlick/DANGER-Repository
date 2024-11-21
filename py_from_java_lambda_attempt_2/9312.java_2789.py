Here is the translation of the Java interface `docking.actions.DockingToolActions` into a Python class:

```python
class DockingToolActions:
    def __init__(self):
        self.local_actions = {}
        self.global_actions = set()
        self.shared_placeholders = {}

    def add_local_action(self, provider: 'ComponentProvider', action: 'DockingActionIf'):
        if provider not in self.local_actions:
            self.local_actions[provider] = []
        self.local_actions[provider].append(action)

    def get_local_action(self, provider: 'ComponentProvider', action_name: str) -> 'DockingActionIf':
        return next((action for action in self.local_actions.get(provider, []) if action.name == action_name), None)

    def remove_local_action(self, provider: 'ComponentProvider', action: 'DockingActionIf'):
        if provider in self.local_actions:
            self.local_actions[provider] = [a for a in self.local_actions[provider] if a != action]

    def add_global_action(self, action: 'DockingActionIf'):
        self.global_actions.add(action)

    def remove_global_action(self, action: 'DockingActionIf'):
        try:
            self.global_actions.remove(action)
        except KeyError:
            pass

    def remove_actions(self, owner: str):
        for provider in list(self.local_actions.keys()):
            if all(a.owner == owner for a in self.local_actions[provider]):
                del self.local_actions[provider]

    def remove_provider_actions(self, provider: 'ComponentProvider'):
        try:
            del self.local_actions[provider]
        except KeyError:
            pass

    def get_actions(self, owner: str) -> set['DockingActionIf']:
        return {action for actions in self.local_actions.values() for action in actions if action.owner == owner}

    def get_all_actions(self) -> set['DockingActionIf']:
        return self.global_actions.union({action for provider_actions in self.local_actions.values() for action in provider_actions})

    def register_shared_action_placeholder(self, placeholder: 'SharedDockingActionPlaceholder'):
        if placeholder not in self.shared_placeholders:
            self.shared_placeholders[placeholder] = None
```

Note that I've used Python's type hinting system to indicate the expected types of method parameters and return values. However, since this is a translation from Java code, these hints are purely informative and do not affect the runtime behavior of the code.

Also note that some methods have been modified slightly to accommodate differences between Java and Python syntax or semantics. For example, in Java, `getLocalAction` returns an object (`DockingActionIf`) if it finds a match, while in Python, I've used the `next` function with a generator expression to achieve similar behavior.