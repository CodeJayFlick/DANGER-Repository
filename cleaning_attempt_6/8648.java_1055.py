class DiffMergeAllAction:
    ACTION_NAME = "Set Merge for All Apply Settings"
    GROUP_NAME = "DIFF_APPLY_ACTION"
    DESCRIPTION = "Change all the difference type apply settings to Merge if possible. Otherwise, change to Replace."

    def __init__(self, provider):
        self.provider = provider
        super().__init__("Set All To Merge", provider.get_plugin().get_name())
        menu_data = {"menu_path": [ACTION_NAME], "group_name": GROUP_NAME}
        popup_menu_data = {"popup_path": [ACTION_NAME], "group_name": GROUP_NAME}
        setMenuBarData(menu_data)
        setPopupMenuData(popup_menu_data)
        setDescription(DESCRIPTION)

    def actionPerformed(self, context):
        self.provider.set_apply_filter(ProgramMergeFilter.ALL, ProgramMergeFilter.MERGE)


class DiffApplySettingsProvider:
    pass


# Example usage
provider = DiffApplySettingsProvider()
action = DiffMergeAllAction(provider)
