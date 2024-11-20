class DataAction:
    def __init__(self, name: str, group: str, data_type: 'DataType', plugin: 'DataPlugin'):
        super().__init__(name, plugin.name, "Shared")
        self.plugin = plugin
        self.data_type = data_type

        menu_data = {'menu': ['Data'], 'sub_menu': [data_type.display_name], 'group': group}
        set_popup_menu_data(menu_data)
        assign_help_id(data_type)

    def get_default_key_stroke(self) -> str:
        return None  # subclasses may override this method

    def init_key_stroke(self, key_stroke: str):
        if not key_stroke:
            return
        self.set_key_binding(key_stroke)

    @property
    def data_type(self):
        return self._data_type

    @data_type.setter
    def data_type(self, value):
        self._data_type = value

    @property
    def plugin(self):
        return self._plugin

    @plugin.setter
    def plugin(self, value):
        self._plugin = value

    def dispose(self) -> None:
        self.data_type = None
        self.plugin = None
        super().dispose()

    def action_performed(self, context: 'ListingActionContext') -> None:
        self.plugin.create_data(context, self.data_type)

    def is_enabled_for_context(self, context: 'ListingActionContext') -> bool:
        return self.plugin.is_create_data_allowed(context)
