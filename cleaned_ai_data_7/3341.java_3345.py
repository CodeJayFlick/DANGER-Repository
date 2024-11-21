class VerticalChoicesPanel:
    def __init__(self):
        self.header_label = None
        self.row_panel = None
        self.rows = []
        self.row_types = []

    def set_title(self, conflict_type: str) -> None:
        if self.header_label is not None:
            self.header_label.setText(f"Resolve {conflict_type} Conflict")

    def set_header(self, text: str) -> None:
        if text and len(text) > 0:
            self.header_label = GDHtmlLabel(ConflictUtility.wrap_as_html(text))
            self.add_component(self.header_label)
        else:
            self.remove_component(self.header_label)

    def add_info_row(self, items: list[str]) -> None:
        for item in items:
            label = MyLabel(item)
            self.add_component(label)

    def add_radio_button_row(self, items: list[str], name: str, conflict_option: int) -> None:
        radio_buttons = []
        for i, item in enumerate(items):
            button = MyRadioButton(item, conflict_option)
            button.setName(name + f"Row{i}")
            self.add_component(button)

    def add_check_box_row(self, items: list[str], name: str, conflict_option: int) -> None:
        check_boxes = []
        for i, item in enumerate(items):
            box = MyCheckBox(item, conflict_option)
            box.setName(name + f"Row{i}")
            self.add_component(box)

    def add_use_for_all_checkbox(self) -> None:
        checkbox = GCheckBox("Use For All")
        self.add_component(checkbox)

    def get_selected_options(self) -> int:
        selected_options = 0
        for i, row in enumerate(self.rows):
            if isinstance(row[0], MyRadioButton) and row[0].isSelected():
                selected_options |= row[0].getOption()
            elif isinstance(row[0], MyCheckBox) and row[0].isSelected():
                selected_options |= row[0].getOption()
        return selected_options

    def get_num_conflicts_resolved(self) -> int:
        num_conflicts = 0
        for i, row in enumerate(self.rows):
            if isinstance(row[0], (MyRadioButton, MyCheckBox)) and row[0].isSelected():
                num_conflicts += 1
        return num_conflicts

    def all_choices_are_resolved(self) -> bool:
        return len([row for row in self.rows if any(isinstance(component, (MyRadioButton, MyCheckBox)) and component.isSelected() for component in row)]) == len(self.rows)

    def clear(self) -> None:
        while self.row_panel.getComponents().length > 0:
            self.remove_component(self.row_panel.getComponent(0))
        self.rows.clear()
        self.row_types.clear()

class GDHtmlLabel(JComponent):
    pass

class MyRadioButton(JRadioButton):
    def __init__(self, text: str, option: int) -> None:
        super().__init__()
        self.option = option
        self.setName(text)

    def getOption(self) -> int:
        return self.option


class MyCheckBox(JCheckBox):
    def __init__(self, text: str, option: int) -> None:
        super().__init__()
        self.option = option
        self.setName(text)

    def getOption(self) -> int:
        return self.option

def add_component(component: JComponent) -> None:
    pass  # Add the component to a container or panel


def remove_component(component: JComponent) -> None:
    pass  # Remove the component from its parent
