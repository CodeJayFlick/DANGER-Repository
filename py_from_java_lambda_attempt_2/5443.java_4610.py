Here's a translation of the Java interface into equivalent Python code:

```Python
class TableService:
    def show_table(self, component_provider_title: str, table_type_name: str,
                   model: 'GhidraProgramTableModel', window_submenu: str,
                   navigatable: 'Navigatable') -> 'TableComponentProvider':
        pass

    def show_table_with_markers(self, component_provider_title: str, table_type_name: str,
                                model: 'GhidraProgramTableModel', marker_color: tuple,
                                marker_icon: 'ImageIcon', window_submenu: str,
                                navigatable: 'Navigatable') -> 'TableComponentProvider':
        pass

    def create_table_chooser_dialog(self, executor: 'TableChooserExecutor',
                                    program: 'Program', name: str,
                                    navigatable: 'Navigatable') -> 'TableChooserDialog':
        pass

    def create_table_chooser_dialog_modal(self, executor: 'TableChooserExecutor',
                                          program: 'Program', name: str,
                                          navigatable: 'Navigatable') -> 'TableChooserDialog':
        pass
```

Note that Python does not have direct equivalents to Java's interfaces or annotations. The above code defines a class `TableService` with methods that match the signatures of the original interface.

Also, note that I've used type hints for function parameters and return types, which is a feature available in Python 3.5+. If you're using an earlier version of Python, you can remove these type hints.