class ApplyAndReplaceMarkupItemAction:
    MENU_GROUP = "APPLY_EDIT_MENU_GROUP"

    def __init__(self, controller, add_to_toolbar):
        super().__init__(controller, "Apply (Replace)")
        
        if add_to_toolbar:
            self.set_tool_bar_data({"icon": APPLY_REPLACE_MENU_ICON, "menu_group": self.MENU_GROUP})
            
        menu_data = {"name": ["Apply (Replace)"], 
                     "icon": APPLY_REPLACE_MENU_ICON, 
                     "menu_group": self.MENU_GROUP}
        
        menu_data["subgroup"] = 2
        self.set_popup_menu_data(menu_data)
        
        self.enabled = False
        
    def get_apply_options(self):
        options = self.controller.get_options()
        vt_options = options.copy()

        vt_options["data_match_type"] = "REPLACE_ALL_DATA"
        
        label_choice = vt_options["labels"]
        if label_choice != "REPLACE_DEFAULT_ONLY":
            vt_options["labels"] = "REPLACE_ALL"

        function_name_choice = vt_options["function_name"]
        if function_name_choice != "REPLACE_DEFAULT_ONLY":
            vt_options["function_name"] = "REPLACE_ALWAYS"
        
        vt_options["function_signature"] = "REPLACE"
        vt_options["calling_convention"] = "NAME_MATCH"
        vt_options["inline"] = "REPLACE"
        vt_options["no_return"] = "REPLACE"
        vt_options["var_args"] = "REPLACE"
        vt_options["call_fixup"] = "REPLACE"
        vt_options["function_return_type"] = "REPLACE_UNDEFINED_DATA_TYPES_ONLY"
        vt_options["parameter_data_types"] = "REPLACE_UNDEFINED_DATA_TYPES_ONLY"
        vt_options["parameter_names"] = "SOURCE_PRIORITY_REPLACE"
        
        # Since this is simply doing a replace, it doesn't need to set parameter name's
        # highest priority or replace if same source flag.
        vt_options["parameter_comments"] = "OVERWRITE_EXISTING"

        vt_options["plate_comment"] = "OVERWRITE_EXISTING"
        vt_options["pre_comment"] = "OVERWRITE_EXISTING"
        vt_options["end_of_line_comment"] = "OVERWRITE_EXISTING"
        vt_options["repeatable_comment"] = "OVERWRITE_EXISTING"
        vt_options["post_comment"] = "OVERWRITE_EXISTING"

        return vt_options

    def get_action_type(self):
        return "REPLACE"


class AbstractMarkupItemAction:
    pass


def main():
    controller = None  # You need to implement this
    action = ApplyAndReplaceMarkupItemAction(controller, True)
    
if __name__ == "__main__":
    main()
