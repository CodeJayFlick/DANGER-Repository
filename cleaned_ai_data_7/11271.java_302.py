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
