class RejectMarkupItemAction:
    MENU_GROUP = "EDIT_MENU_GROUP"

    def __init__(self, controller, add_to_toolbar):
        super().__init__(controller, "Reject")
        
        if add_to_toolbar:
            self.toolbar_data = {"icon": REJECTED_ICON, "menu_group": MENU_GROUP}
        else:
            self.popup_menu_data = [{"label": "Reject", "icon": REJECTED_ICON}, 
                                     {"group": MENU_GROUP}]

    def get_tag_type(self):
        return VTMarkupItemConsideredStatus.REJECT

# You would need to define these variables elsewhere in your code
REJECTED_ICON = None  # Replace with the actual icon or image
VTMarkupItemConsideredStatus = object()  # This is a Python equivalent of Java enum, replace it as needed
