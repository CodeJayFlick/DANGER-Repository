class FindReferencesToAddressAction:
    def __init__(self, plugin: 'LocationReferencesPlugin', sub_group_position: int):
        super().__init__(plugin.get_tool(), plugin.name)
        self.set_popup_menu_data({
            "menu_group": LocationReferencesService.MENU_GROUP,
            "name": self.__class__.__name__,
            "description": "Show References To",
            "mnemonic": None,
            "subgroup_position": str(sub_group_position),
        })

    def is_enabled_for_context(self, context: 'NavigatableActionContext') -> bool:
        if not isinstance(context, ListingActionContext):
            return False
        return super().is_enabled_for_context(context)
