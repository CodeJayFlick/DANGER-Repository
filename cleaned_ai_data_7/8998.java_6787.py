class MarkupTypeFilter:
    def __init__(self):
        self.name = "Markup Type"

    def create_checkbox_infos(self):
        markup_types = VTMarkupTypeFactory.get_markup_types()
        for markup_type in markup_types:
            checkbox = GCheckBox(markup_type.display_name)
            checkbox.set_selected(True)
            listener = ItemListener(lambda e: print("Filter status changed"))
            checkbox.add_item_listener(listener)
            info = MarkupTypeCheckBoxInfo(checkbox, markup_type)
            self.checkbox_infos.append(info)

class MarkupTypeCheckBoxInfo:
    def __init__(self, checkbox, markup_type):
        super().__init__(checkbox)
        self.markup_type = markup_type

    def matches_status(self, adapter):
        if not self.get_checkbox().get_selected():
            return False
        return adapter.get_markup_type() == self.markup_type


# Usage:
filter = MarkupTypeFilter()
