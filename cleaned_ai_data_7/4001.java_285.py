import tkinter as tk
from typing import Dict

class EditLabelAction:
    def __init__(self, plugin: 'LabelMgrPlugin') -> None:
        self.plugin = plugin
        super().__init__("Edit Label", plugin.name)
        self.set_popup_menu_data({"Edit Label...": None}, "Label")
        self.set_key_binding_data({"Ctrl+L": None})

    @property
    def popup_menu_data(self) -> Dict[str, str]:
        return {"Edit Field Name...": None}

    @popup_menu_data.setter
    def set_popup_menu_data(self, value: Dict[str, str]) -> None:
        self.popup_menu_data = value

    @property
    def key_binding_data(self) -> Dict[str, str]:
        return {"Ctrl+L": None}

    @key_binding_data.setter
    def set_key_binding_data(self, value: Dict[str, str]) -> None:
        self.key_binding_data = value

    def is_enabled_for_context(self, context: 'ListingActionContext') -> bool:
        if LabelMgrPlugin.get_component(context) is not None:
            return True
        symbol = self.plugin.get_symbol(context)
        if symbol is None or symbol.is_external():
            return False
        if symbol.symbol_type == SymbolType.FUNCTION and isinstance(context.location, OperandFieldLocation):
            return False
        return True

    def action_performed(self, context: 'ListingActionContext') -> None:
        self.plugin.edit_label_callback(context)
