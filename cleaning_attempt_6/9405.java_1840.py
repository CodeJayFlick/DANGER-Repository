class ActionState(T):
    def __init__(self, name: str, icon: any, user_data: T) -> None:
        self.name = name
        self.icon = icon
        self.user_data = user_data

    @property
    def name(self) -> str:
        return self._name

    @property
    def icon(self) -> any:
        return self._icon

    @property
    def user_data(self) -> T:
        return self._user_data

    @user_data.setter
    def set_user_data(self, value: T) -> None:
        self._user_data = value

    def get_help_location(self) -> HelpLocation | None:
        return self._help_location

    def set_help_location(self, help_location: HelpLocation | None) -> None:
        self._help_location = help_location

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ActionState):
            return False
        if self.name != other.name or self.user_data != other.user_data:
            return False
        return True

    def __hash__(self) -> int:
        return hash((self.name, self.user_data))

    def __str__(self) -> str:
        return f"{self.name}: {self.user_data}"
