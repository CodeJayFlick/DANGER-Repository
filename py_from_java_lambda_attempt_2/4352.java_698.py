Here is the translation of the given Java code into Python:

```Python
class CreateLibraryAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Create Library", self.plugin.get_name())
        self.set_popup_menu_data(["Create Library"], "0External")
        self.enabled = False

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        self._enabled = value

    def is_enabled_for_context(self, context):
        selection_paths = context.get_selected_symbol_tree_paths()
        if len(selection_paths) == 1:
            object_ = selection_paths[0].get_last_path_component()
            if isinstance(object_, (ImportsCategoryNode, SymbolTreeRootNode)):
                return True
        return False

    def action_performed(self, context):
        tree = context.get_context_object()
        if tree.is_filtered():
            Msg.show_warn(self.__class__, tree, "Create Library Not Allowed",
                          "Cannot create library name while the tree is filtered!")
            return
        self.create_external_library(context)

    def create_external_library(self, context):
        selection_paths = context.get_selected_symbol_tree_paths()

        program = context.get_program()
        parent = program.get_global_namespace()
        node = selection_paths[0].get_last_path_component()

        if isinstance(node, SymbolTreeRootNode):
            node = node.get_child("Imports")

        new_external_library_name = self.create_external_library(program, parent)
        if new_external_library_name is None:
            return

        program.flush_events()
        context.get_symbol_tree().start_editing(node, new_external_library_name)

    def create_external_library(self, program, parent):
        import_name = "NewLibrary"
        transaction_id = program.start_transaction("Create Library")
        try:
            symbol_table = program.get_symbol_table()
            one_up = 0
            while True:
                namespace = symbol_table.create_external_library(import_name, SourceType.USER_DEFINED)
                if namespace is not None:
                    break
                import_name = f"NewLibrary({one_up})"

        except DuplicateNameException as e:
            Msg.debug(self.__class__, "Failed to create library name: " + str(e))
            return None

        finally:
            program.end_transaction(transaction_id, True)

        return import_name


# Usage example
if __name__ == "__main__":
    class SymbolTreePlugin:
        def get_name(self):
            pass

    plugin = SymbolTreePlugin()
    action = CreateLibraryAction(plugin)
```

Please note that Python does not have direct equivalent of Java's `package`, so I did not include the package declaration in this code. Also, some classes and methods were removed as they are not directly related to the main functionality of creating a library.