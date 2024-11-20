from abc import ABCMeta, abstractmethod
import typing as t

class AbstractDynamicTableColumn(metaclass=ABCMeta):
    def __init__(self) -> None:
        # default constructor
        pass

    @abstractmethod
    def get_column_name(self) -> str:
        ...

    @abstractmethod
    def get_value(self, row_object: t.Any, settings: dict, data: t.Any, service_provider: t.Any) -> t.Any:
        ...

class SettingsDefinition(t.Generic[t.T]):
    NO_SETTINGS_DEFINITIONS = []

INTEGER_RADIX_SETTING = "DECIMAL"
INTEGER_SIGNEDNESS_MODE_SETTING = "DEF"

FLOATING_POINT_PRECISION_SETTING = "DEF"

INTEGER_SETTINGS_DEFINITIONS = [INTEGER_RADIX_SETTING, INTEGER_SIGNEDNESS_MODE_SETTING]
FLOATING_POINT_SETTINGS_DEFINITIONS = [FLOATING_POINT_PRECISION_SETTING]

class AbstractDynamicTableColumn(metaclass=ABCMeta):
    def __init__(self) -> None:
        self.has_configured_default_settings: bool = False
        self.default_settings_definitions: list[SettingsDefinition] = []

    @abstractmethod
    def get_column_name(self) -> str:
        ...

    def configure_default_settings(self) -> None:
        if not self.has_configured_default_settings:
            column_class = type(self).get_column_class()
            if NumericUtilities.is_integer_type(column_class):
                self.default_settings_definitions = INTEGER_SETTINGS_DEFINITIONS
            elif NumericUtilities.is_floating_point_type(column_class):
                self.default_settings_definitions = FLOATING_POINT_SETTINGS_DEFINITIONS
            self.has_configured_default_settings: bool = True

    def get_settings_definitions(self) -> list[SettingsDefinition]:
        if not self.has_configured_default_settings:
            self.configure_default_settings()
        return self.default_settings_definitions

class NumericUtilities:
    @staticmethod
    def is_integer_type(class_: t.Any) -> bool:
        ...

    @staticmethod
    def is_floating_point_type(class_: t.Any) -> bool:
        ...
