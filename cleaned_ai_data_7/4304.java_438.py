class StackEditorManager:
    def __init__(self):
        self.editor_map = {}
        self.plugin = None

    def dispose(self):
        for editor in list(self.editor_map.values()):
            if hasattr(editor, 'dismiss'):
                editor.dismiss()
            else:
                print("No dismiss method found")
        self.editor_map.clear()

    def edit(self, function):
        if function not in self.editor_map:
            editor = StackEditorProvider(self.plugin, function)
            editor.add_editor_listener(self)  # listen for editor closing
            self.editor_map[function] = editor

    def program_closed(self, closed_program):
        self.dismiss_editors(closed_program)

    @property
    def is_edit_in_progress(self):
        return len(self.editor_map) > 0


class StackEditorProvider:
    def __init__(self, plugin, function):
        self.plugin = plugin
        self.function = function

    def add_editor_listener(self, listener):
        pass  # implement this method in your subclass

    @property
    def needs_save(self):
        return False  # implement this property in your subclass


class StackEditorManagerPlugin:
    def get_tool(self):
        pass  # implement this method in your subclass

    def show_component_provider(self, component_provider, is_modal=False):
        pass  # implement this method in your subclass
