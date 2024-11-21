class ApplyAndAddAsPrimaryMarkupItemAction:
    MENU_GROUP = "APPLY_EDIT_MENU_GROUP"

    def __init__(self, controller: 'VTController', add_to_toolbar: bool):
        super().__init__(controller, "Apply (Add As Primary)")
        
        if add_to_toolbar:
            self.set_tool_bar_data({"icon": APPLY_ADD_MENU_ICON, "group": MENU_GROUP})
            
        menu_data = {"menu_items": ["Apply (Add As Primary)",], 
                     "icon": APPLY_ADD_MENU_ICON, "group": MENU_GROUP}
        self.set_popup_menu_data(menu_data)
        
        self.enabled = False
        self.help_location = HelpLocation("VersionTrackingPlugin", "Add_As_Primary_Markup_Item")

    def get_apply_options(self):
        options = self.controller.get_options()
        vt_options = options.copy()
        vt_options["function_name"] = FunctionNameChoices.ADD_AS_PRIMARY
        
        return vt_options

    def get_action_type(self):
        return VTMarkupItemApplyActionType.ADD_AS_PRIMARY
