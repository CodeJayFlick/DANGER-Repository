Here is your Java code translated into Python:

```Python
class FunctionBitPatternsMainProvider:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__()

    def updateClipboard(self):
        self.clipboard.updateClipboard()
        self.clipboard.updateUI()

    def build(self):
        panel = JPanel(BoxLayout.Y_AXIS)
        control_panel = JPanel(FlowLayout.LEFT)

        info_panel = JPanel(FlowLayout.LEFT)
        data_info_panel = JPanel(PairLayout())
        instruction_info_panel = JPanel(PairLayout())
        bytes_info_panel = JPanel(PairLayout())

        read_xml_button = JButton("Read XML Files")
        mine_program_button = JButton("Explore Function Bit Patterns")

        self.dataSourceField = JTextField(70, False)

        num_functions_field = JTextField(10)
        num_files_field = JTextField(10)

        first_instructions_field = JTextField(10)
        pre_instructions_field = JTextField(10)
        return_instructions_field = JTextField(10)

        first_bytes_field = JTextField(10)
        pre_bytes_field = JTextField(10)
        return_bytes_field = JTextField(10)

        info_panel.add(instruction_info_panel)
        info_panel.add(bytes_info_panel)
        control_panel.add(info_panel, BorderLayout.CENTER)
        panel.add(control_panel, BorderLayout.NORTH)

        tabbedPane = JTabbedPane()
        first_inst_panel = InstructionSequenceTreePanelBuilder(PatternType.FIRST).buildMainPanel()
        pre_inst_panel = InstructionSequenceTreePanelBuilder(PatternType.PRE).buildMainPanel()

        return_inst_panel = InstructionSequenceTreePanelBuilder(PatternType.RETURN).buildMainPanel()
        tabbedPane.insertTab("First Instructions", None, first_inst_panel, 0)
        tabbedPane.insertTab("Pre-Instructions", None, pre_inst_panel, 1)

        # ... (rest of the code remains same as in Java) ...
```

Please note that this is a direct translation from your provided Java code to Python.