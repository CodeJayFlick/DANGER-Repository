class ReplaceFirstMarkupItemAction:
    MENU_GROUP = "APPLY_EDIT_MENU_GROUP"

    def __init__(self, controller: 'VTController', addToToolbar: bool) -> None:
        super().__init__(controller, "Apply (Replace First Only)")
        
        self.replaced_icon = ResourceManager.load_image("images/replaced_obj.png")
        warning_icon = ResourceManager.load_image("images/warning_obj.png")
        scaled_warning_icon = ResourceManager.get_scaled_icon(warning_icon, 12, 12)
        multi_icon = MultiIcon(self.replaced_icon, False)

        refresh_icon_width = self.replaced_icon.width
        refresh_icon_height = self.replaced_icon.height
        warning_icon_width = warning_icon.width
        warning_icon_height = warning_icon.height

        x = refresh_icon_width - warning_icon_width
        y = refresh_icon_height - warning_icon_height

        translate_icon = TranslateIcon(warning_icon, x, y)
        multi_icon.add_icon(translate_icon)

        if addToToolbar:
            tool_bar_data = ToolBarData(multi_icon, self.MENU_GROUP)
            set_tool_bar_data(tool_bar_data)

        menu_data = MenuData(["Apply (Replace First Only)"], self.replaced_icon, self.MENU_GROUP)
        menu_data.set_menu_sub_group("2")
        set_popup_menu_data(menu_data)

        self.enabled = False
        help_location = HelpLocation("VersionTrackingPlugin", "Replace_First_Markup_Item")
        set_help_location(help_location)

    def get_apply_options(self) -> 'ToolOptions':
        options = controller.get_options()
        vt_options = options.copy()
        vt_options.set_enum(DATA_MATCH_DATA_TYPE, ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY)
        
        return vt_options

    def get_action_type(self) -> 'VTMarkupItemApplyActionType':
        return VTMarkupItemApplyActionType.REPLACE_FIRST_ONLY
