Here is the translation of the Java code into Python:

```Python
class DirectoryList:
    def __init__(self, chooser, model):
        self.chooser = chooser
        self.model = model
        super().__init__()
        self.build()

    def build(self):
        self.setLayoutOrientation("vertical")
        cell_renderer = FileListCellRenderer(chooser=self.chooser)
        self.set_cell_renderer(cell_renderer)

        font_metrics = cell_renderer.get_font_metrics()
        fixed_height = max(font_metrics.height, 16) + min(font_metrics.height / 3, 5)
        set_fixed_cell_height(fixed_height)
        set_fixed_cell_width(-1)

        mouse_listener = GMouseListenerAdapter()
        self.add_mouse_listener(mouse_listener)

        key_adapter = KeyAdapter()
        self.add_key_listener(key_adapter)

        list_editor_label = GDLabel()
        list_editor_field = JTextField(name="LIST_EDITOR_FIELD")
        list_editor_field.add_key_listener(key_adapter)
        list_editor_field.add_focus_listener(FocusAdapter())

        list_editor = JPanel(orientation=JPanel.VERTICAL)
        list_editor.add(list_editor_label, BorderLayout.WEST)
        list_editor.add(list_editor_field, BorderLayout.CENTER)

        self.add(list_editor)

    def handle_enter_key(self):
        selected_indices = get_selected_indices()
        if len(selected_indices) == 0:
            chooser.ok_callback()
        elif len(selected_indices) > 1:
            chooser.ok_callback()
        else:
            file = model.get_file(selected_indices[0])
            if chooser.model.is_directory(file):
                chooser.set_current_directory(file)
            else:
                chooser.user_chose_file(file)

    def maybe_select_item(self, e):
        point = e.point
        index = location_to_index(point)
        if index < 0:
            return
        self.select(index)

    def handle_double_click(self):
        selected_files = []
        for i in get_selected_indices():
            file = model.get_file(i)
            selected_files.append(file)

        if len(selected_files) == 1:
            file = selected_files[0]
            if chooser.model.is_directory(file):
                chooser.set_current_directory(file)
            else:
                chooser.user_chose_file(file)

    def update_chooser_for_selection(self):
        selected_files = []
        for i in get_selected_indices():
            file = model.get_file(i)
            selected_files.append(file)
        chooser.user_selected_files(selected_files)

    @property
    def auto_lookup(self):
        return GListAutoLookup(self)


class FileListCellRenderer:
    def __init__(self, chooser):
        self.chooser = chooser

    def get_font_metrics(self):
        # This method should be implemented based on the actual font used in your application.
        pass


# Other classes and methods are not provided as they were missing from the original Java code
```

Please note that this is a direct translation of the given Java code into Python. The resulting Python code may or may not work correctly, depending on how well it was translated.