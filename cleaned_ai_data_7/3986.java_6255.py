class SelectionScopeWidget:
    def __init__(self, plugin, title, dialog):
        self.plugin = plugin
        self.dialog = dialog
        self.search_ranges = []
        self.search_all_rb = None
        self.search_selection_rb = None

    def get_search_range(self):
        if self.search_all_rb.isSelected():
            return update_search_range_all()
        else:
            return update_search_range_by_selection()

    def update_search_range_all(self):
        if not self.plugin:
            return []
        iterator = self.plugin.get_current_program().get_memory().get_loaded_and_initialized_address_set().get_address_ranges()
        while iterator.has_next():
            self.search_ranges.append(iterator.next())
        return self.search_ranges

    def update_search_range_by_selection(self):
        if not self.search_selection_rb.isSelected():
            return
        self.search_ranges.clear()
        program_selection = self.plugin.get_program_selection()
        if program_selection and (program_selection.min_address is not None) and (program_selection.max_address is not None):
            iterator = program_selection.get_address_ranges().iterator()
            while iterator.has_next():
                self.search_ranges.append(iterator.next())
        return self.search_ranges

    def create_content(self):
        content_panel = JPanel()
        content_panel.setLayout(BoxLayout(content_panel, BoxLayout.X_AXIS))
        content_panel.setAlignmentX(Component.LEFT_ALIGNMENT)

        self.search_all_rb = JRadioButton("Entire Program", "When active, the entire program will be used for the search.")
        self.search_all_rb.setSelected(True)
        content_panel.add(self.search_all_rb)

        self.search_selection_rb = JRadioButton("Search Selection", "When active, code selections on the listing will change the search range.")
        content_panel.add(self.search_selection_rb)

        button_group = ButtonGroup()
        button_group.add(self.search_all_rb)
        button_group.add(self.search_selection_rb)

        return content_panel

    class SearchSelectionAction(AbstractAction):
        def actionPerformed(self, event):
            self.update_search_range_by_selection()
            self.dialog.get_message_panel().clear()

    class SearchAllAction(AbstractAction):
        def actionPerformed(self, event):
            self.update_search_range_all()
            self.dialog.get_message_panel().clear()


class JPanel:
    pass


class JRadioButton:
    def __init__(self, name, tooltip):
        self.name = name
        self.text = name
        self.tooltip_text = tooltip

    @property
    def isSelected(self):
        return True  # Assume the radio button is selected by default.


class ButtonGroup:
    def add(self, rb):
        pass


class AbstractAction:
    def actionPerformed(self, event):
        pass


# Usage example:

plugin = None  # Replace with your actual plugin instance.
title = "Title"  # Replace with your desired title.
dialog = None  # Replace with your actual dialog instance.

widget = SelectionScopeWidget(plugin, title, dialog)
content_panel = widget.create_content()
