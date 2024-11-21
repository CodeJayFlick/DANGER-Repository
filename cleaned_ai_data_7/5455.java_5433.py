class AddressFieldOptionsPropertyEditor:
    def __init__(self):
        self.editor_component = self.build_editor()

    def build_editor(self):
        panel = JPanel()
        label = GDLabel("Show Block Name", SwingConstants.RIGHT)
        label.set_tooltip_text("Prepends the Memory Block name to address in the address field.")
        panel.add(label)
        show_blockname_checkbox = GCheckBox()
        show_blockname_checkbox.set_tooltip_text("Prepends the Memory Block name to address in the address field.")
        panel.add(show_blockname_checkbox)

        label = GDLabel("Minimum Number of Address digits", SwingConstants.RIGHT)
        label.set_tooltip_text("Specifies the minimum number of hex digits to display the address (The minimum is actually the smaller of this number and the number of digits in largest possible address in that address space.)")
        panel.add(label)
        min_digits_field = IntegerTextField(2)
        min_digits_field.allow_negative_values = False
        min_digits_field.set_decimal_mode()
        min_digits_field.max_value = 32
        min_digits_field.get_component().set_tooltip_text("Specifies the minimum number of hex digits to display the address (The minimum is actually the smaller of this number and the number of digits in largest possible address in that address space.)")
        panel.add(min_digits_field.get_component())

        label = GDLabel("Fully Pad With Leading Zeros", SwingConstants.RIGHT)
        label.set_tooltip_text("Pads Addresses with leading zeros to the full size of the largest possible address.")
        panel.add(label)
        pad_checkbox = GCheckBox()
        panel.add(pad_checkbox)

        label = GDLabel("Justification", SwingConstants.RIGHT)
        label.set_tooltip_text("Specifies the justification for address text in the address field. The address text will clip on the opposite side of the justification.")
        panel.add(label)
        justification_combobox = GhidraComboBox(["Left", "Right"])
        justification_combobox.set_tooltip_text("Specifies the justification for address text in the address field. The address text will clip on the opposite side of the justification.")
        panel.add(justification_combobox)

        show_blockname_checkbox.add_item_listener(lambda event: self.fire_property_change())
        justification_combobox.add_item_listener(lambda event: self.fire_property_change())

        pad_checkbox.add_item_listener(lambda event:
            enabled = not pad_checkbox.get_selected()
            min_digits_field.set_enabled(enabled)
            self.fire_property_change()
        )
        min_digits_field.add_change_listener(lambda event: self.fire_property_change())

    def set_value(self, value):
        if isinstance(value, AddressFieldOptionsWrappedOption):
            address_padding_option = value
            self.set_local_values(address_padding_option)

    def get_min_number_of_digits(self):
        return int(min_digits_field.get_text())

    def set_local_values(self, address_padding_option):
        show_blockname_checkbox.set_selected(address_padding_option.show_block_name())
        if "Right" == justification_combobox.get_selected_item():
            right_just = True
        else:
            right_just = False

        pad_checkbox.set_selected(address_padding_option.pad_with_zeros())

    def clone_address_pad_values(self):
        new_option = AddressFieldOptionsWrappedOption()
        new_option.set_pad_with_zeros(pad_checkbox.get_selected())
        new_option.set_minimum_hex_digits(int(min_digits_field.get_text()))
        new_option.set_show_block_name(show_blockname_checkbox.get_selected())
        new_option.set_right_justify("Right" == justification_combobox.get_selected_item())

    def get_custom_editor(self):
        return self.editor_component

class AddressFieldOptionsWrappedOption:
    pass
