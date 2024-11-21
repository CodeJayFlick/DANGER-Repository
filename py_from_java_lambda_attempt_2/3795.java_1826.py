Here is the translation of the Java code into Python:

```Python
class SetFlowOverrideDialog:
    DEFAULT_CHOICE = "-DEFAULT-"

    def __init__(self, tool, instruction=None):
        self.tool = tool
        self.instruction = instruction
        if instruction:
            self.program = instruction.get_program()
        else:
            self.program = None

        super().__init__("Modify Instruction Flow", True, False, True, False)
        self.add_work_panel(self.build_main_panel())
        self.add_ok_button()
        self.add_cancel_button()
        self.set_default_button("okButton")
        self.set_remember_size(False)

    def build_main_panel(self):
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 2))

        if self.instruction:
            main_panel.add(self.build_current_flow_panel())
        main_panel.add(self.build_flow_override_panel())

        if self.instruction and self.instruction.get_flow_type().is_conditional():
            main_panel.add(self.build_note_panel("*Conditional flow will be preserved"))

        return main_panel

    def build_current_flow_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))

        flow_type = self.instruction.get_flow_type()

        panel.add(GLabel("Current Flow: " + flow_type.name() + ("*" if flow_type.is_conditional() else "")))

        panel.add(Box.createGlue())
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        return panel

    def build_note_panel(self, note):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))
        panel.add(GLabel(note))
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        return panel

    def build_flow_override_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))

        self.flow_override_combobox = GhidraComboBox()
        self.flow_override_combobox.add_item(SetFlowOverrideDialog.DEFAULT_CHOICE)
        for flow_override in FlowOverride.values():
            if flow_override == FlowOverride.NONE:
                continue
            self.flow_override_combobox.add_item(flow_override)

        flow_override = self.instruction.get_flow_override() if self.instruction else None

        if not flow_override:
            self.flow_override_combobox.set_selected(SetFlowOverrideDialog.DEFAULT_CHOICE)
        elif flow_override:
            self.flow_override_combobox.set_selected(flow_override)

        panel.add(GLabel("Instruction Flow:"))
        panel.add(self.flow_override_combobox)

        panel.add(Box.createGlue())
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        return panel

    def get_tool(self):
        return self.tool

    def ok_callback(self):
        if self.execute_command():
            self.close()

    def cancel_callback(self):
        self.status_text = ""
        self.close()

    def execute_command(self):
        flow = FlowOverride.NONE
        choice = self.flow_override_combobox.get_selected()
        if not SetFlowOverrideDialog.DEFAULT_CHOICE == choice:
            flow = choice

        if not self.instruction:
            self.tool.execute_background_command(SetFlowOverrideCmd(self.selection, flow), self.program)
        elif self.instruction.get_flow_override() == flow:
            return True
        else:
            self.tool.execute_background_command(SetFlowOverrideCmd(self.instruction.min_address(), flow), self.program)

        return True

class PluginTool:
    def execute_background_command(self, command, program):
        pass

class SetFlowOverrideCmd:
    def __init__(self, min_address=None, flow=FlowOverride.NONE):
        self.min_address = min_address
        self.flow = flow

# Define FlowOverride enum here
```

Please note that this is a direct translation of the Java code into Python. The equivalent classes and methods in Python are not exactly identical to their Java counterparts due to differences between the two languages.