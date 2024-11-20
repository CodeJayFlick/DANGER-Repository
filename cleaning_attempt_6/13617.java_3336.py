import tkinter as tk
from typing import List, Tuple

class CdtProjectFieldEditor:
    def __init__(self, name: str, label_text: str, parent_widget: tk.Widget) -> None:
        self.name = name
        self.label_text = label_text
        self.parent_widget = parent_widget

    def change_pressed(self) -> str | None:
        dialog_title = "CDT project selection"
        message = "Select an open CDT project:"
        cdt_projects = CdtUtils.get_cdt_projects()
        elements: List[Tuple[str, ...]] = [(p.name,) for p in cdt_projects]
        dialog = tk.toplevel(self.parent_widget)
        label_provider = LabelProvider()
        element_list_selection_dialog = tk.ElementListSelectionDialog(dialog, label_provider)
        element_list_selection_dialog.title(dialog_title)
        element_list_selection_dialog.message(message)
        element_list_selection_dialog.set_elements(*elements)
        result: List[tk.Widget] | None = element_list_selection_dialog.result
        if result and len(result) > 0:
            return str(result[0])
        return None

class LabelProvider:
    def get_text(self, item: tk.Widget) -> str:
        # implement this method to provide the text for each list item
        pass

class CdtUtils:
    @staticmethod
    def get_cdt_projects() -> List[str]:
        # implement this method to retrieve a list of open CDT projects
        pass
