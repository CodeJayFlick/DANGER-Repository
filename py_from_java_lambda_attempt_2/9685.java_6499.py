Here is the translation of the Java code into Python:

```Python
class ListSelectionTableDialog:
    def __init__(self, title: str, list_data: list):
        self.model = RowObjectTableModel(list_data)
        super().__init__(title, True, False, True, False)
        add_work_panel(self.build())
        add_ok_button()
        add_cancel_button()
        update_ok_button_enablement()
        set_focus_component(filter_panel)

    def __init__(self, title: str, model: RowObjectTableModel):
        self.model = model
        super().__init__(title, True, False, True, False)
        add_work_panel(self.build())
        add_ok_button()
        add_cancel_button()
        update_ok_button_enablement()
        set_focus_component(filter_panel)

    def ok_callback(self):
        selected_rows = g_table.get_selected_rows()
        if len(selected_rows) > 0:
            self.selected_values.clear()
            for row in selected_rows:
                model_row = filter_panel.get_model_row(row)
                row_object = self.model.get_row_object(model_row)
                self.selected_values.append(row_object)
            self.selected_value = self.selected_values[0] if not self.selected_values else None
            close()

    def close(self):
        super().close()
        filter_panel.dispose()

    def build(self) -> JComponent:
        panel = JPanel(BorderLayout())
        panel.set_border(EmptyBorder20, 20, 20))
        g_table = GTable()
        g_table.get_selection_model().setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        scroll = JScrollPane(g_table)
        filter_panel = GTableFilterPanel(g_table, self.model)
        panel.add(scroll, BorderLayout.CENTER)
        panel.add(filter_panel, BorderLayout.SOUTH)
        g_table.add_key_listener(KeyAdapter() {
            def key_pressed(self, e):
                if e.get_key_char() == '\n':
                    ok_callback()
                    e.consume()

        })
        g_table.get_selection_model().add_list_selection_listener(lambda e: update_ok_button_enablement())
        g_table.add_mouse_listener(MouseAdapter() {
            def mouse_clicked(self, e):
                if e.get_button() == MouseEvent.BUTTON1 and e.get_click_count() == 2:
                    ok_callback()
        })

    return panel

    def update_ok_button_enablement(self) -> None:
        set_ok_enabled(not g_table.get_selection_model().is_empty())

    @property
    def selected_item(self):
        return self.selected_value

    @property
    def selected_items(self):
        return self.selected_values

    def show(self, parent: Component) -> T:
        set_selection_mode(False)
        DockingWindowManager.show_dialog(parent, self)
        return get_selected_item()

    def show_select_multiple(self, parent: Component) -> list[T]:
        set_selection_mode(True)
        DockingWindowManager.show_dialog(parent, self)
        return get_selected_items()

class GTableFilterPanel:
    def __init__(self, g_table: GTable, model: RowObjectTableModel):
        self.g_table = g_table
        self.model = model

    @property
    def model_row(self) -> int:
        # implement this method to convert row index from filter panel to the actual data
        pass

class RowObjectTableModel(list[T]):
    def __init__(self, list_data: list):
        super().__init__()
        for item in list_data:
            self.append(item)

    @property
    def name(self) -> str:
        return "Name"

    @property
    def column_name(self) -> str:
        return self.name

    def get_column_class(self, index: int) -> type:
        return str

    def is_cell_editable(self, row_index: int, col_index: int) -> bool:
        return False

    def get_model_data(self) -> list[T]:
        return super().copy()

    def get_column_value_for_row(self, t: T, index: int) -> object:
        return t
```

Please note that the translation is not a direct conversion from Java to Python. Some methods and variables are missing in this code as they were not provided in your original question.