Here is the translation of the Java code into Python:

```Python
class GatherParamPanel:
    def __init__(self, state):
        self.state = state
        self.parameters = {}
        self.shown = False

    def get_parameter(self, key):
        return self.parameters.get(key)

    def clear_parameters(self):
        self.parameters.clear()
        # remove all() method is not available in Python's JPanel equivalent (Frame or QWidget)
        pass

    def add_parameter_regardless(self, key, label, type, default_value):
        if type == 0:  # STRING
            display_component = None
        elif type == 1:  # FILE
            title_string = "SELECT FILE"
            panel = GhidraFileChooserPanel(title_string, "", true)
            panel.set_file_name(str(default_value))
            self.parameters[key] = {"display_component": panel, "type": type}
            display_component = panel
        elif type == 2:  # DIRECTORY
            title_string = "SELECT DIRECTORY"
            panel = GhidraFileChooserPanel(title_string, "", true)
            panel.set_file_name(str(default_value))
            self.parameters[key] = {"display_component": panel, "type": type}
            display_component = panel
        elif type == 3:  # ADDRESS
            address_input = AddressInput()
            if self.state.current_program is not None:
                address_input.set_address_factory(self.state.current_program.get_address_factory())
            address_input.select_default_address_space()
            address_input.select()
            if default_value is not None:
                address_input.set_value(str(default_value))
            display_component = address_input
        elif type == 4:  # INTEGER
            text_field = JTextField()
            if default_value is not None:
                text_field.text = str(default_value)
            self.parameters[key] = {"display_component": text_field, "type": type}
            display_component = text_field

        panel.add(GLabel(label))
        panel.add(display_component)

    def add_parameter(self, key, label, type, default_value):
        if self.parameters.get(key) is not None or self.state.environment_var.get(key) is not None:
            return
        self.add_parameter_regardless(key, label, type, default_value)

    def set_params_in_state(self):
        for key in self.parameters.keys():
            param_component = self.parameters[key]
            display_component = param_component["display_component"]
            if isinstance(display_component, AddressInput) and self.state.current_program is not None:
                address_input = display_component
                self.state.add_environment_var(key, str(address_input.get_address()))
            elif isinstance(display_component, GhidraFileChooserPanel):
                fileChooserPanel = display_component
                self.state.add_environment_var(key, File(fileChooserPanel.file_name))
            else:  # INTEGER or STRING
                text_field = display_component
                if type == 4:
                    val = int(text_field.text)
                    self.state.add_environment_var(key, val)
                elif type != 0:
                    self.state.add_environment_var(key, str(text_field.text))

    def current_program_changed(self):
        for key in self.parameters.keys():
            param_component = self.parameters[key]
            display_component = param_component["display_component"]
            if isinstance(display_component, AddressInput) and self.state.current_program is not None:
                address_input = display_component
                address_input.set_address_factory(self.state.current_program.get_address_factory())
                address_input.select_default_address_space()
                address_input.select()

    def panel_shown(self):
        return self.shown

    def set_shown(self, shown):
        self.shown = shown


class ParamComponent:
    def __init__(self, display_component, type):
        self.display_component = display_component
        self.type = type

    def get_display_component(self):
        return self.display_component

    def get_type(self):
        return self.type
```

Please note that Python does not have direct equivalent of Java's JPanel and GridLayout. You can use tkinter or PyQt for GUI programming in Python.