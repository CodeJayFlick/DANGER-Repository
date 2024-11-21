class BitsInputDialogComponentProvider:
    TOTAL_BITS_LABEL = "Total Bits"
    DEFAULT_TOTAL_BITS = 32
    POST_BITS_LABEL = "Post Bits"
    DEFAULT_POST_BITS = 16

    def __init__(self, title):
        self.total_bits_box = None
        self.pre_bits_box = None
        super().__init__(title)
        panel = self.create_panel()
        self.add_work_panel(panel)
        self.add_ok_button()
        self.add_cancel_button()
        self.set_default_button(self.ok_button)

    def create_panel(self):
        main_panel = JPanel()  # Assuming a custom class for JPanel, replace with actual implementation
        pair_layout = PairLayout()  # Assuming a custom class for PairLayout, replace with actual implementation

        main_panel.setLayout(pair_layout)
        total_bits_label = GLabel(TOTAL_BITS_LABEL)  # Assuming a custom class for GLabel, replace with actual implementation
        self.total_bits_box = IntegerTextField()
        self.total_bits_box.set_value(DEFAULT_TOTAL_BITS)
        main_panel.add(total_bits_label.get_component())
        main_panel.add(self.total_bits_box.get_component())

        pre_bits_label = GLabel(POST_BITS_LABEL)  # Assuming a custom class for GLabel, replace with actual implementation
        self.pre_bits_box = IntegerTextField()
        self.pre_bits_box.set_value(DEFAULT_POST_BITS)
        main_panel.add(pre_bits_label.get_component())
        main_panel.add(self.pre_bits_box.get_component())

        return main_panel

    def get_total_bits(self):
        return int(self.total_bits_box.get_value())

    def get_post_bits(self):
        return int(self.pre_bits_box.get_value())


# Assuming a custom class for the above methods, replace with actual implementation
class JPanel:
    pass


class PairLayout:
    pass


class GLabel:
    pass


class IntegerTextField:
    def __init__(self):
        self.value = None

    def set_value(self, value):
        self.value = value

    def get_component(self):
        return None  # Assuming a custom implementation for the component, replace with actual code
