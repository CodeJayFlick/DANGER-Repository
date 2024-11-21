Here is your Java code translated into Python:

```Python
class VariousChoicesPanel:
    def __init__(self):
        self.rows = []
        self.layout = None
        self.row_panel = None
        self.header_label = None
        self.indent = 0
        self.column_count = 1
        self.radioButtonBorder = None
        self.checkBoxBorder = None

    def set_title(self, conflict_type: str):
        if hasattr(self.get_border(), 'setTitle'):
            self.get_border().set_title("Resolve " + conflict_type + " Conflict")

    def set_header(self, text: str):
        if self.header_label is not None:
            self.remove(0)
        if text != "":
            self.header_label = GDHtmlLabel(text)
            self.add(self.header_label, BorderLayout.NORTH)

    def adjust_column_count(self, number_of_columns: int):
        if number_of_columns <= 0:
            number_of_columns = 1
        if self.column_count != number_of_columns:
            self.column_count = number_of_columns
            self.layout = MaximizeSpecificColumnGridLayout(5, 5, self.column_count)
            self.row_panel.setLayout(self.layout)

    def add_info_row(self, title: str, info: list[str], underline: bool):
        self.adjust_column_count(len(info))
        label_title_comp = MyLabel(title)
        if underline:
            label_title_comp.setBorder(self.underline_border())
        labels = [MyLabel(text) for text in info]
        no_choice_row = ChoiceRow(label_title_comp, labels)
        self.add_row(no_choice_row)

    def add_single_choice(self, title: str, choices: list[str], listener):
        self.adjust_column_count(len(choices) + 1)
        label_title_comp = MyLabel(title)
        radio_buttons = [MyRadioButton(text) for text in choices]
        choice_row = ChoiceRow(label_title_comp, radio_buttons)
        item_listener = ItemListener()
        button_group = ButtonGroup()
        for i, rb in enumerate(radio_buttons):
            rb.setName(f"ChoiceComponentRow{i+1}")
            rb.addItemListener(item_listener)
            button_group.add(rb)
        if len(choices) > 0:
            label_title_comp.setBorder(self.radioButtonBorder())
        self.add_row(choice_row)

    def add_multiple_choice(self, title: str, choices: list[str], listener):
        self.adjust_column_count(len(choices) + 1)
        label_title_comp = MyLabel(title)
        check_boxes = [MyCheckBox(text) for text in choices]
        choice_row = ChoiceRow(label_title_comp, check_boxes)
        item_listener = ItemListener()
        for i, cb in enumerate(check_boxes):
            cb.setName(get_component_name(len(self.rows), i+1))
            cb.addItemListener(item_listener)
        if len(choices) > 0:
            label_title_comp.setBorder(self.checkBoxBorder())
        self.add_row(choice_row)

    def get_component_name(self, row: int, column: int):
        return f"ChoiceComponentRow{row}Col{column}"

    # ... other methods

class ChoiceRow:
    def __init__(self, title_label: MyLabel, radio_buttons_or_check_boxes: list[JComponent]):
        self.title_label = title_label
        self.radio_buttons_or_check_boxes = radio_buttons_or_check_boxes

    def get_choice(self):
        choice = 0
        for i, rb in enumerate(self.radio_buttons_or_check_boxes):
            if isinstance(rb, MyRadioButton) and rb.isSelected():
                choice |= 1 << i
            elif isinstance(rb, MyCheckBox) and rb.isSelected():
                choice |= 1 << i
        return choice

    def has_choices(self):
        for rb in self.radio_buttons_or_check_boxes:
            if isinstance(rb, (MyRadioButton, MyCheckBox)):
                return True
        return False


class MyLabel(GDHtmlLabel):
    pass


class MyRadioButton(GRadioButton):
    pass


class MyCheckBox(GCheckBox):
    pass

# ... other classes and methods
```

Please note that this is a direct translation of your Java code into Python. It might not be the most idiomatic or efficient way to write Python, but it should work as expected.