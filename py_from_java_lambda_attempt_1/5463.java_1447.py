Here is the translation of the Java code into Python:

```Python
class ArrayElementPropertyEditor:
    SHOW_MULTI_ELEMENTS_LABEL = "Group Array Elements"
    GROUP_SIZE_LABEL = "Elements Per Line"

    DESCRIPTIONS = [f"Groups multiple array elements on the same listing line", f"Number of array elements to show on a line"]

    def __init__(self):
        self.editor_component = self.build_editor()

    def build_editor(self):
        panel = VerticalLayout(3)

        group_elements_checkbox = GCheckBox(SHOW_MULTI_ELEMENTS_LABEL)
        group_elements_checkbox.setSelected(True)
        group_elements_checkbox.setToolTip(f"Groups multiple array elements on the same listing line")

        panel.add(group_elements_checkbox)

        elements_per_line_field, elements_label = self.create_local_prefix_textfield(GROUP_SIZE_LABEL, f"Number of array elements to show on a line", panel)

        group_elements_checkbox.addItemListener(lambda e: self.item_state_changed(e))

        panel.setBorder(CompoundBorder(EmptyBorder(10), TitledBorder("Grouping")))

        return panel

    def create_local_prefix_textfield(self, label_text, tooltip_text, parent):
        text_field = IntegerTextField(10)
        text_field.setAllowNegativeValues(False)
        text_field.setEnabled(True)

        text_field_panel = JPanel()
        text_field_panel.setBorder(EmptyBorder(0, 10, 0, 0))

        elements_label = GDLabel(label_text)
        text_field_panel.add(elements_label)
        text_field_panel.add(text_field.getComponent())

        text_field.addChangeListener(lambda e: self.state_changed(e))
        parent.add(text_field_panel)

        return text_field

    def item_state_changed(self, event):
        enabled = group_elements_checkbox.isSelected()
        elements_per_line_field.setEnabled(enabled)
        elements_label.setEnabled(enabled)
        fire_property_change()

    @property
    def value(self):
        if not isinstance(value, ArrayElementWrappedOption):
            return None
        self.element_wrapped_option = value
        set_local_values(self.element_wrapped_option)
        fire_property_change()
        return self.element_wrapped_option

    def set_local_values(self, namespace_option):
        if namespace_option.show_multiple_array_element_per_line() != group_elements_checkbox.isSelected():
            group_elements_checkbox.setSelected(namespace_option.show_multiple_array_element_per_line())
        if namespace_option.get_array_elements_per_line() != elements_per_line_field.getValue():
            elements_per_line_field.setValue(namespace_option.get_array_elements_per_line())

    def clone_namespace_values(self):
        new_option = ArrayElementWrappedOption()
        new_option.set_show_multiple_array_element_per_line(group_elements_checkbox.isSelected())
        new_option.set_array_elements_per_line(elements_per_line_field.getValue())
        return new_option

    @property
    def option_descriptions(self):
        return DESCRIPTIONS

    @property
    def option_names(self):
        return [SHOW_MULTI_ELEMENTS_LABEL, GROUP_SIZE_LABEL]

    @property
    def value(self):
        return self.clone_namespace_values()

    @property
    def custom_editor(self):
        return self.editor_component

    @property
    def supports_custom_editor(self):
        return True


class ArrayElementWrappedOption:
    pass  # This class is not implemented in the given Java code, so it's left as a placeholder.
```

Please note that this translation assumes you have some basic Python knowledge and familiarity with GUI programming.