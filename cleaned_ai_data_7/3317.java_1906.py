class ConflictPanel:
    USE_FOR_ALL_CHECKBOX = "UseForAllPropertyConflictCheckBox"

    def __init__(self):
        pass

    def create_use_for_all_checkbox(self):
        use_for_all_cb = GCheckBox("unknown")
        use_for_all_cb.set_name(USE_FOR_ALL_CHECKBOX)
        return use_for_all_cb


class ChoiceComponent:
    pass


def get_use_all_string(conflict_type: str) -> str:
    return f"Use the selected option for resolving all remaining '{conflict_type}' conflicts."


def set_conflict_type(self, conflict_type: str):
    self.use_for_all_cb.set_text(get_use_all_string(conflict_type))


def set_use_for_all(self, use_for_all: bool):
    if self.use_for_all_cb.get_selected() != use_for_all:
        self.use_for_all_cb.set_selected(use_for_all)


class GCheckBox:
    def __init__(self, text: str):
        pass

    def get_selected(self) -> bool:
        return True  # Replace with actual implementation


def has_choice(self) -> bool:
    return False  # Replace with actual implementation


def get_use_for_all_choice(self) -> int:
    return 0  # Replace with actual implementation


class DockingWidgetsCheckboxGCheckBox(GCheckBox):
    pass
