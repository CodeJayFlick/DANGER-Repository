class AssociationStatusFilter:
    def __init__(self):
        self.name = "Association Status"
        self.checkBoxInfos = []

    def create_checkbox_infos(self):
        for status in VTAssociationStatus.values():
            checkbox = GCheckBox(status.get_display_name(), True)
            listener = ItemListener()
            def on_item_state_changed(event):
                fire_status_changed(get_filter_status())
            listener.on_item_state_change += lambda event: on_item_state_changed(event)

            self.checkBoxInfos.append(AssociationStatusCheckBoxInfo(checkbox, status))

    class AssociationStatusCheckBoxInfo:
        def __init__(self, checkbox, association_status):
            super().__init__(checkbox)
            self.association_status = association_status

        def matches_status(self, match):
            if not self.checkbox.isSelected():
                return False
            return match.get_association().get_status() == self.association_status


class GCheckBox:
    pass  # This is a custom class that doesn't exist in Python's standard library.


VTAssociationStatus = [status for status in ["Unknown", "Unassociated", "Associated"]]


def fire_status_changed(status):
    pass  # This method should be implemented based on the actual use case.

def get_filter_status():
    pass  # This method should return the current filter status.
