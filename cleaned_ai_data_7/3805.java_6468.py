class AbstractConvertAction:
    def __init__(self, plugin: 'EquatePlugin', action_name: str, is_signed: bool):
        self.plugin = plugin
        self.is_signed = is_signed
        super().__init__(action_name, plugin.get_name())

    @property
    def popup_menu_data(self) -> 'MenuData':
        return MenuData(['Convert'], 'Convert')

    def is_enabled_for_context(self, context: 'ListingActionContext') -> bool:
        location = context.location
        if not isinstance(location, OperandFieldLocation):
            return False

        scalar = self.plugin.get_scalar(context)
        if scalar is None:
            return False

        if self.is_signed and scalar.signed_value >= 0:
            return False

        code_unit = self.plugin.get_code_unit(context)
        if isinstance(code_unit, Data):
            data_type = code_unit.base_data_type
            if not isinstance(data_type, AbstractIntegerDataType):
                return False

        menu_name = self.menu_name(context.program, scalar, isinstance(code_unit, Data))
        if menu_name is None:
            return False

        self.popup_menu_data.set_menu_item_name(menu_name)
        return True

    def action_performed(self, context: 'ListingActionContext'):
        command = ConvertCommand(self, context)
        if context.has_selection():
            self.plugin.get_tool().execute_background_command(command, context.program)
        else:
            self.plugin.get_tool().execute(command, context.program)

    @abstractmethod
    def menu_name(self, program: object, scalar: 'Scalar', is_data: bool) -> str:
        pass

    @abstractmethod
    def convert_to_string(self, program: object, scalar: 'Scalar', is_data: bool) -> str:
        pass

    def get_format_choice(self):
        return -1

    def is_signed_choice(self):
        return self.is_signed


class MenuData:
    def __init__(self, items: list[str], title: str):
        self.items = items
        self.title = title

    @property
    def menu_item_name(self) -> str:
        return self.title

    @menu_item_name.setter
    def menu_item_name(self, value: str):
        self.title = value


class ConvertCommand:
    pass  # Command implementation is not provided in the given Java code.
