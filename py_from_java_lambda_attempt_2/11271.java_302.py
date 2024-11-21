Here is the translation of the Java code to Python:
```
import collections

class UndoRedoToolState:
    def __init__(self, plugins, domain_object):
        self.states = []
        for plugin in plugins:
            state = plugin.get_undo_redo_state(domain_object)
            if state is not None:
                self.states.append((plugin, state))

    def restore_tool(self, domain_object):
        for ps in self.states:
            ps[0].restore_undo_redo_state(domain_object, ps[1])


class PluginState:
    def __init__(self, plugin, state):
        self.plugin = plugin
        self.state = state

    def restore_undo_redo_state(self, domain_object):
        if not self.plugin.is_disposed():
            self.plugin.restore_undo_redo_state(domain_object, self.state)
```
Note that I've used the `collections` module to create a list of tuples in the `UndoRedoToolState` class, since Python doesn't have an equivalent to Java's `List<PluginState>` type. Similarly, I've used tuple unpacking (`ps[0]`, `ps[1]`) instead of accessing fields on each object.

Also, I assume that the `isDisposed()` and `restore_undo_redo_state()` methods are implemented elsewhere in your codebase, since they're not defined here.