Here is the translation of the Java code to Python:
```
class FileListCellRenderer:
    def __init__(self, chooser):
        self.chooser = chooser
        self.model = chooser.get_model()
        self.set_alternate_row_background_colors(False)

    def get_item_text(self, file):
        return self.chooser.get_display_name(file)

    def get_list_cell_renderer_component(self, list, file, index, selected, cell_has_focus):
        super().get_list_cell_renderer_component(list, file, index, selected, cell_has_focus)
        self.set_icon(self.model.get_icon(file))
        return self
```
Note that I've used Python's built-in `class` syntax to define the class, and the `def` keyword to define methods. The rest of the code is straightforward translations from Java to Python.

Also, since there are no specific libraries or imports required for this translation (i.e., it doesn't rely on any external dependencies), I didn't include any import statements in the Python version.