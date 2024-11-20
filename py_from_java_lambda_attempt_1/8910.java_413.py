Here is the translation of the given Java code into equivalent Python:

```Python
class ReplaceDefaultMarkupItemAction:
    MENU_GROUP = VTPlugin.APPLY_EDIT_MENU_GROUP
    
    def __init__(self, controller, add_to_toolbar):
        super().__init__(controller, "Apply (Replace Default Only)")
        
        replaced_icon = ResourceManager.load_image("images/replaced.png")
        warning_icon = ResourceManager.get_scaled_icon(ResourceManager.load_image("images/warning.png"), 12, 12)
        refresh_icon_width = replaced_icon.width
        refresh_icon_height = replaced_icon.height
        
        x = refresh_icon_width - warning_icon.width
        y = refresh_icon_height - warning_icon.height
        
        translate_icon = TranslateIcon(warning_icon, x, y)
        
        multi_icon = MultiIcon(replaced_icon)
        multi_icon.add_icon(translate_icon)
        
        if add_to_toolbar:
            self.set_tool_bar_data(new ToolBarData(multi_icon, MENU_GROUP))
            
        menu_data = new MenuData(["Apply (Replace Default Only)"], replaced_icon, MENU_GROUP)
        menu_data.set_menu_sub_group("2")
        self.set_popup_menu_data(menu_data)
        
        self.setEnabled(False)
        help_location = HelpLocation("VersionTrackingPlugin", "Replace_Default_Markup_Item")
        self.set_help_location(help_location)

    def get_apply_options(self):
        options = controller.get_options()
        vt_options = options.copy()
        vt_options['FUNCTION_NAME'] = 'REPLACE_DEFAULT_ONLY'
        vt_options['LABELS'] = 'REPLACE_DEFAULT_ONLY'
        vt_options['FUNCTION_RETURN_TYPE'] = 'REPLACE_UNDEFINED_DATA_TYPES_ONLY'
        vt_options['PARAMETER_DATA_TYPES'] = 'REPLACE_UNDEFINED_DATA_TYPES_ONLY'
        vt_options['PARAMETER_NAMES'] = 'REPLACE_DEFAULTS_ONLY'
        vt_options['DATA_MATCH_DATA_TYPE'] = 'REPLACE_DEFAULTS_ONLY'

        return vt_options

    def get_action_type(self):
        return VTMarkupItemApplyActionType.REPLACE_DEFAULT_ONLY
```

Please note that Python does not support direct translation of Java code. It is a different language with its own syntax and structure, so the equivalent Python code may look quite different from the original Java code.