class EditorStateFactory:
    cache = {}

    def __init__(self):
        pass

    def get_editor_state(self, options, name, listener):
        option_id = options.get_id(name)
        editor_state = self.cache.get(option_id)
        if editor_state is None:
            editor_state = EditorState(options, name)
            self.cache[option_id] = editor_state
        editor_state.add_listener(listener)  # this class uses a set to avoid duplicate listeners
        return editor_state

    def clear(self, options, name):
        del self.cache[options.get_id(name)]

    def clear_all(self):
        self.cache.clear()
