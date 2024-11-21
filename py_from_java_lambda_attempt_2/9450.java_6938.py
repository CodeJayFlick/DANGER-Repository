Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import scrolledtext

class OptionsPanel:
    def __init__(self, root_name, options, show_restore_defaults_button):
        self.root_node = None
        self.g_tree = None
        self.current_options_editor = None
        self.editor_map = {}
        self.view_panel = tk.Frame()
        self.default_panel = tk.Frame()
        self.options_editor_container = tk.Frame()
        self.restore_default_panel = tk.Frame()
        self.update_manager = None

        if len(options) == 1:
            self.root_node = OptionsRootTreeNode(options[0])
        else:
            self.root_node = OptionsRootTreeNode(root_name, options)

        self.g_tree = GTree(self.root_node)
        self.g_tree.add_g_tree_selection_listener(self.process_selection)
        self.g_tree.set_data_transformer(OptionsDataTransformer())

        view_panel_layout = tk.Frame()
        view_panel_layout.pack(side=tk.LEFT, fill=tk.BOTH)
        split-pane = ttk.Splitter(orient='horizontal')
        split-pane.pack(fill=tk.X)

        g_tree_frame = tk.Frame(split-pane)
        g_tree_frame.pack(fill=tk.BOTH, expand=1)
        self.g_tree.pack(fill=tk.BOTH, expand=1)

        view_panel_frame = tk.Frame(split-pane)
        view_panel_frame.pack(fill=tk.BOTH, expand=1)
        self.view_panel.pack(fill=tk.BOTH, expand=1)

    def dispose(self):
        if self.update_manager is not None:
            self.update_manager.dispose()
        self.g_tree.dispose()

    def create_restore_defaults_button(self):
        button = tk.Button("Restore Defaults")
        button['command'] = lambda: self.restore_default_options_for_current_editor()
        return button

    def get_focus_component(self):
        return self.g_tree.filter_field

    def restore_default_options_for_current_editor(self):
        selected_path = self.g_tree.get_selection_path()
        if selected_path is None:
            return
        node = selected_path[-1]
        options = node.options
        options.restore_default_values()
        editor = options.get_options_editor()
        if editor is not None:
            editor.reload()
        for option_name in node.option_names:
            self.editor_state_factory.clear(options, option_name)
        self.process_selection(node)

    def cancel(self):
        entry_set = set(self.editor_map.items())
        for entry in entry_set:
            try:
                editor = entry[1]
                editor.cancel()
            except Exception as e:
                msg = str(e) if e is not None else 'Error Resetting Options'
                title = f"Error Resetting Options on {entry[0].name}"
                messagebox.showerror(self, self, title, title + '\n' + msg, e)

    def apply(self):
        status = True
        entry_set = set(self.editor_map.items())
        for entry in entry_set:
            try:
                editor = entry[1]
                editor.apply()
            except OptionsVetoException as ove:
                messagebox.showwarn(self, self, "Invalid Option Value", f"Attempted to set an option to an invalid value: {ove.message}")
            except Exception as e:
                status = False
                msg = str(e) if e is not None else 'Error Setting Options'
                title = f"Error Setting Options on {entry[0].name}"
                messagebox.showerror(self, self, title, title + '\n' + msg, e)
        return status

    def display_category(self, category, filter_text):
        root_node = self.g_tree.model_root
        categories = [root_node.name] + category.split(Options.DELIMITER_STRING)
        self.g_tree.set_filter_text(filter_text)
        self.g_tree.set_selected_node_by_name_path(categories)

    def create_default_panel(self):
        panel = tk.Frame()
        label = scrolledtext.ScrolledText("To change Options, select a Folder or Option Group from the\n" + "Options Tree and change the Option settings.")
        label.pack(fill=tk.BOTH)
        return panel

    def process_selection(self, node):
        if node is None:
            self.set_view_panel(self.default_panel, node)
            return
        current_options_editor = self.get_options_editor(node)
        if current_options_editor is not None:
            editor_component = current_options_editor.get_editor_component(node.options, self.editor_state_factory)
            if editor_component is not None:
                editor_component.pack(fill=tk.BOTH, expand=1)

    def get_selected_options(self):
        selected_path = self.g_tree.get_selection_path()
        if selected_path is None:
            return None
        node = selected_path[-1]
        options = node.options
        return options

    def set_view_panel(self, component, node):
        self.view_panel.remove_widgets(*self.view_panel.winfo_children())
        self.view_panel.add(component)
        self.set_help_location(component, node)

    def set_help_location(self, component, node):
        if node is None:
            help.clear_help(self)
        else:
            options = node.options
            location = options.get_options_help_location()
            if location is not None:
                help.register_help(self, location)

class OptionsDataTransformer:
    def transform(self, node):
        results = super().transform(node)
        for option_name in node.option_names:
            add_details(options, option_name, results)
        return results

def add_details(options, option_name, results):
    property_editor = options.get_registered_property_editor(option_name)
    if isinstance(property_editor, CustomOptionsEditor):
        add_option_details((property_editor), results)
    else:
        description = options.get_description(option_name)
        results.append(option_name)
        results.append(description)

def add_option_details(editor, results):
    option_names = editor.get_option_names()
    for name in option_names:
        results.append(name)
    descriptions = editor.get_option_descriptions()
    for desc in descriptions:
        results.append(desc)