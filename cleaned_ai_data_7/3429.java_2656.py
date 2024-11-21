class StoredAnalyzerTimesPropertyEditor:
    def __init__(self):
        self.times = None

    def supports_custom_editor(self):
        return True

    def get_option_names(self):
        if not self.times:
            return []
        return self.times.get_task_names()

    def get_option_descriptions(self):
        return []

    def set_value(self, value):
        if not isinstance(value, StoredAnalyzerTimes):
            return
        self.times = value
        self.fire_property_change()

    def get_value(self):
        return self.times.clone() if hasattr(self.times, 'clone') else self.times

    def get_custom_editor(self):
        return self.build_editor()

    def build_editor(self):
        panel = JPanel()
        
        if not self.times or not self.times:
            label = JLabel("No Data Available")
            panel.add(label)
            return panel
        
        for task_name in self.get_option_names():
            label = GDLabel(task_name, SwingConstants.RIGHT)
            label.set_tooltip_text(task_name)
            panel.add(label)

            time_ms = self.times.get_time(task_name) if hasattr(self.times, 'get_time') else None
            value_field = JTextField(StoredAnalyzerTimes.format_time_ms(time_ms))
            value_field.setEditable(False)
            value_field.setHorizontalAlignment(SwingConstants.RIGHT)
            panel.add(value_field)

        label = GDLabel("TOTAL", SwingConstants.RIGHT)
        label.set_font(label.get_font().derive_font(Font.BOLD))
        panel.add(label)

        total_time = self.times.get_total_time() if hasattr(self.times, 'get_total_time') else None
        value_field = JTextField(StoredAnalyzerTimes.format_time_ms(total_time))
        value_field.setEditable(False)
        value_field.setHorizontalAlignment(SwingConstants.RIGHT)
        value_field.set_border(BorderFactory.create_line_border(Color.black, 2))
        panel.add(value_field)

        return panel

class JPanel:
    def __init__(self):
        pass

    def add(self, component):
        pass

class JLabel:
    def __init__(self, text):
        self.text = text
        self.tooltip_text = None

    def set_tooltip_text(self, tooltip_text):
        self.tooltip_text = tooltip_text

    def get_font(self):
        return Font()

    def derive_font(self, font):
        return font


class GDLabel(JLabel):
    pass


class JTextField:
    def __init__(self, text):
        self.text = text
        self.editable = True

    def set_editable(self, editable):
        self.editable = editable

    def get_horizontal_alignment(self):
        return SwingConstants.LEFT

    def set_horizontal_alignment(self, alignment):
        pass


class StoredAnalyzerTimes:
    @staticmethod
    def format_time_ms(time_ms):
        if time_ms is None:
            return "None"
        return str(time_ms)

    def clone(self):
        # This method should be implemented in the actual class.
        pass

    def get_task_names(self):
        # This method should be implemented in the actual class.
        pass

    def get_time(self, task_name):
        # This method should be implemented in the actual class.
        return None

    def get_total_time(self):
        # This method should be implemented in the actual class.
        return None
