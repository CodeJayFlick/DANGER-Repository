Here is the translation of the Java code into Python:

```Python
class OptionsManager:
    def __init__(self, tool):
        self.tool = tool
        self.options_map = {}

    def dispose(self):
        if self.options_dialog:
            self.options_dialog.dispose()
        for options in self.options_map.values():
            options.dispose()

    def get_options(self, category):
        opt = self.options_map.get(category)
        if not opt:
            opt = ToolOptions(category)
            opt.add_options_listener(self)
            self.options_map[category] = opt
        return opt

    def register_option_name_changed(self, old_name, new_name):
        if old_name in self.options_map:
            options = self.options_map.pop(old_name)
            options.name = new_name
            self.options_map[new_name] = options

    def has_options(self, category):
        return category in self.options_map

    def show_options_dialog(self, category, filter_text):
        if self.options_dialog and self.options_dialog.is_visible():
            self.options_dialog.to_front()
            return
        self.options_dialog = create_options_dialog()
        self.options_dialog.display_category(category, filter_text)
        self.tool.show_dlg(self.options_dialog)

    def get_options_array(self):
        options_list = list(self.options_map.values())
        options_list.sort(key=lambda x: x.name)
        return tuple(options_list)

    def deregister_owner(self, owner_plugin):
        delete_list = []
        for key in self.options_map:
            opt = self.options_map[key]
            if not any(opt.get_option_names()):
                delete_list.append(opt.name)
        remove_unused_options(delete_list)

    def get_config_state(self):
        root = Element("OPTIONS")
        for category, options in self.options_map.items():
            if has_non_default_values(options):
                root.append(options.to_xml_root(False))
        return root

    @staticmethod
    def has_non_default_values(options):
        option_names = list(options.get_option_names())
        for name in option_names:
            if not options.is_default_value(name):
                return True
        return False

    def remove_unused_options(self, delete_list=None):
        if delete_list is None:
            delete_list = []
            for key in self.options_map:
                opt = self.options_map[key]
                if not any(opt.get_option_names()):
                    delete_list.append(key)
        for name in delete_list:
            options = self.options_map.pop(name)
            options.remove_options_listener(self)

    def set_config_state(self, root):
        for child in root.children():
            options = ToolOptions(child)
            old_options = self.options_map.get(options.name)
            if not old_options:
                options.add_options_listener(self)
            else:
                options.take_listeners(old_options)
                options.register_options(old_options)
            self.options_map[options.name] = options

    def edit_options(self):
        if not self.options_map:
            print("No Options set in this tool")
            return
        if self.options_dialog and self.options_dialog.is_visible():
            self.options_dialog.to_front()
            return
        self.options_dialog = create_options_dialog()
        self.tool.show_dlg(self.options_dialog)

    def validate_options(self):
        for options in self.options_map.values():
            options.validate_options()

    @staticmethod
    def create_options_dialog():
        if not self.options_map:
            return None

        key_binding_options = get_options(DockingToolConstants.KEY_BINDINGS)
        path = None
        if self.options_dialog and self.options_dialog.is_visible():
            path = self.options_dialog.get_selected_path()
            self.options_dialog.dispose()

            old_editor = key_binding_options.get_options_editor()
            old_editor.dispose()

        key_binding_options.register_options_editor(KeyBindingOptionsEditor())
        dialog = OptionsDialog("Options for " + self.tool.name, "Options", get_editable_options(), None, True)
        dialog.set_selected_path(path)
        return dialog

    @staticmethod
    def get_editable_options():
        return [tool.get_option() for tool in self.options_map.values()]

class ToolOptions:
    def __init__(self, name):
        self.name = name
        self.options_listener_list = []

    def add_options_listener(self, listener):
        self.options_listener_list.append(listener)

    def remove_options_listener(self, listener):
        if listener in self.options_listener_list:
            self.options_listener_list.remove(listener)

    @staticmethod
    def to_xml_root(is_default=False):
        # TO DO: implement this method
        pass

class OptionsDialog:
    def __init__(self, title, name, options_array, parent=None, is_modal=True):
        self.title = title
        self.name = name
        self.options_array = options_array
        self.parent = parent
        self.is_modal = is_modal
        self.selected_path = None

    @staticmethod
    def get_selected_path():
        return self.selected_path

    def to_front(self):
        # TO DO: implement this method
        pass

class OptionsEditor:
    def apply(self):
        # TO DO: implement this method
        pass

    def cancel(self):
        # TO DO: implement this method
        pass

    def reload(self):
        # TO DO: implement this method
        pass

    def dispose(self):
        # TO DO: implement this method
        pass

class KeyBindingOptionsEditor(OptionsEditor):
    def __init__(self, tool, options):
        self.tool = tool
        self.options = options
        self.panel = KeyBindingsPanel(tool, options)

    @staticmethod
    def get_options_array():
        return [tool.get_option() for tool in self.options_map.values()]

class OptionsComparator:
    def compare(self, o1, o2):
        # TO DO: implement this method
        pass

# Usage example:

options_manager = OptionsManager(tool)
...
```

Please note that the translation is not perfect and some parts of the code might need to be adjusted according to your specific requirements.