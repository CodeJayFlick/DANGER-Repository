class VTMarcupItem:
    USER_DEFINED_ADDRESS_SOURCE = "User Defined"
    FUNCTION_ADDRESS_SOURCE = "Function"
    DATA_ADDRESS_SOURCE = "Data"

    def __init__(self):
        pass

    def can_apply(self) -> bool:
        raise NotImplementedError("canApply method must be implemented")

    def can_unapply(self) -> bool:
        raise NotImplementedError("canUnapply method must be implemented")

    def apply(self, action_type: str, options=None) -> None:
        raise NotImplementedError("apply method must be implemented")

    def unapply(self) -> None:
        raise NotImplementedError("unapply method must be implemented")

    @property
    def default_destination_address_source(self):
        return self.USER_DEFINED_ADDRESS_SOURCE

    @default_destination_address_source.setter
    def set_default_destination_address(self, address: str, source: str = USER_DEFINED_ADDRESS_SOURCE) -> None:
        if not isinstance(address, str):
            raise TypeError("Address must be a string")
        if not isinstance(source, str):
            raise TypeError("Source must be a string")

    @property
    def destination_address_edit_status(self):
        return "Editable"

    @destination_address_edit_status.setter
    def set_destination_address(self, address: str) -> None:
        if not isinstance(address, str):
            raise TypeError("Address must be a string")
        self._set_destination_address(address)

    def _set_destination_address(self, address: str) -> None:
        pass

    @property
    def considered_status(self):
        return "Unconsidered"

    @considered_status.setter
    def set_considered(self, status: int) -> None:
        if not isinstance(status, int):
            raise TypeError("Status must be an integer")
        self._set_considered(status)

    def _set_considered(self, status: int) -> None:
        pass

    @property
    def status(self) -> str:
        return "Unknown"

    @status.setter
    def set_status(self, status: str) -> None:
        if not isinstance(status, str):
            raise TypeError("Status must be a string")
        self._set_status(status)

    def _set_status(self, status: str) -> None:
        pass

    @property
    def status_description(self) -> str:
        return "No description"

    @status_description.setter
    def set_status_description(self, description: str) -> None:
        if not isinstance(description, str):
            raise TypeError("Description must be a string")
        self._set_status_description(description)

    def _set_status_description(self, description: str) -> None:
        pass

    @property
    def association(self) -> object:
        return "Unknown"

    @association.setter
    def set_association(self, association: object) -> None:
        if not isinstance(association, object):
            raise TypeError("Association must be an object")
        self._set_association(association)

    def _set_association(self, association: object) -> None:
        pass

    @property
    def source_address(self) -> str:
        return "Unknown"

    @source_address.setter
    def set_source_address(self, address: str) -> None:
        if not isinstance(address, str):
            raise TypeError("Address must be a string")
        self._set_source_address(address)

    def _set_source_address(self, address: str) -> None:
        pass

    @property
    def source_location(self) -> object:
        return "Unknown"

    @source_location.setter
    def set_source_location(self, location: object) -> None:
        if not isinstance(location, object):
            raise TypeError("Location must be an object")
        self._set_source_location(location)

    def _set_source_location(self, location: object) -> None:
        pass

    @property
    def source_value(self) -> str:
        return "Unknown"

    @source_value.setter
    def set_source_value(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Value must be a string")
        self._set_source_value(value)

    def _set_source_value(self, value: str) -> None:
        pass

    @property
    def destination_address(self) -> str:
        return "Unknown"

    @destination_address.setter
    def set_destination_address(self, address: str) -> None:
        if not isinstance(address, str):
            raise TypeError("Address must be a string")
        self._set_destination_address(address)

    def _set_destination_address(self, address: str) -> None:
        pass

    @property
    def destination_location(self) -> object:
        return "Unknown"

    @destination_location.setter
    def set_destination_location(self, location: object) -> None:
        if not isinstance(location, object):
            raise TypeError("Location must be an object")
        self._set_destination_location(location)

    def _set_destination_location(self, location: object) -> None:
        pass

    @property
    def destination_address_source(self) -> str:
        return "Unknown"

    @destination_address_source.setter
    def set_destination_address_source(self, source: str = USER_DEFINED_ADDRESS_SOURCE) -> None:
        if not isinstance(source, str):
            raise TypeError("Source must be a string")
        self._set_destination_address_source(source)

    def _set_destination_address_source(self, source: str) -> None:
        pass

    @property
    def current_destination_value(self) -> str:
        return "Unknown"

    @current_destination_value.setter
    def set_current_destination_value(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Value must be a string")
        self._set_current_destination_value(value)

    def _set_current_destination_value(self, value: str) -> None:
        pass

    @property
    def original_destination_value(self) -> str:
        return "Unknown"

    @original_destination_value.setter
    def set_original_destination_value(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Value must be a string")
        self._set_original_destination_value(value)

    def _set_original_destination_value(self, value: str) -> None:
        pass

    @property
    def supports_apply_action(self) -> bool:
        return False

    @supports_apply_action.setter
    def set_supports_apply_action(self, action_type: str) -> None:
        if not isinstance(action_type, str):
            raise TypeError("Action type must be a string")
        self._set_supports_apply_action(action_type)

    def _set_supports_apply_action(self, action_type: str) -> None:
        pass

    @property
    def markup_type(self) -> object:
        return "Unknown"

    @markup_type.setter
    def set_markup_type(self, type: object) -> None:
        if not isinstance(type, object):
            raise TypeError("Type must be an object")
        self._set_markup_type(type)

    def _set_markup_type(self, type: object) -> None:
        pass

