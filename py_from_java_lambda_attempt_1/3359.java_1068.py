Here's your Java code translated into Python:

```Python
class PropertyListMergePanel:
    LATEST_BUTTON_NAME = 'LATEST'
    CHECKED_OUT_BUTTON_NAME = 'CHECKED OUT'
    ORIGINAL_BUTTON_NAME = 'ORIGINAL'

    def __init__(self, merge_manager: ProgramMultiUserMergeManager, total_conflicts):
        self.merge_manager = merge_manager
        self.total_conflicts = total_conflicts

    def set_conflict_info(self, conflict_index: int, info: ConflictInfo) -> None:
        self.merge_manager.clear_status_text()
        self.conflict_panel.set_conflict_info(info)
        self.count_panel.update_count(conflict_index, self.total_conflicts)

    @property
    def selected_option(self):
        return self.conflict_panel.selected_option

    def create(self) -> None:
        self.count_panel = ConflictCountPanel()
        self.conflict_panel = self.create_conflict_panel()

        layout = BorderLayout(0, 20)
        border = EmptyBorder(10, 5, 0, 5)

        self.setLayout(layout)
        self.setBorder(border)
        self.add(self.count_panel, 'NORTH')
        self.add(self.conflict_panel, 'CENTER')

    def create_conflict_panel(self) -> ConflictPanel:
        change_listener = ChangeListener()
        conflict_panel = ConflictPanel(change_listener)

        preferred_size = conflict_panel.get_preferred_size()
        conflict_panel.set_preferred_size((400, preferred_size[1]))

        return conflict_panel

    def set_use_for_all(self, use_for_all: bool) -> None:
        self.conflict_panel.set_use_for_all(use_for_all)

    @property
    def use_for_all(self):
        return self.conflict_panel.use_for_all


class ProgramMultiUserMergeManager:
    pass  # This class is not implemented in the provided Java code, so it's left as a placeholder.


class ConflictInfo:
    pass  # This class is not implemented in the provided Java code, so it's left as a placeholder.


class ConflictCountPanel:
    def update_count(self, conflict_index: int, total_conflicts):
        pass  # This method is not implemented in the provided Java code, so it's left as a placeholder.


class ConflictPanel:
    LATEST_BUTTON_NAME = 'LATEST'
    CHECKED_OUT_BUTTON_NAME = 'CHECKED OUT'
    ORIGINAL_BUTTON_NAME = 'ORIGINAL'

    def __init__(self, change_listener: ChangeListener):
        self.change_listener = change_listener

    @property
    def selected_option(self) -> int:
        pass  # This property is not implemented in the provided Java code, so it's left as a placeholder.

    def set_conflict_info(self, info: ConflictInfo) -> None:
        pass  # This method is not implemented in the provided Java code, so it's left as a placeholder.

    @property
    def use_for_all(self):
        pass  # This property is not implemented in the provided Java code, so it's left as a placeholder.


class BorderLayout:
    def __init__(self, hgap: int = 0, vgap: int = 0):
        self.hgap = hgap
        self.vgap = vgap


class EmptyBorder:
    def __init__(self, top: int, left: int, bottom: int, right: int):
        self.top = top
        self.left = left
        self.bottom = bottom
        self.right = right


class ChangeListener:
    pass  # This class is not implemented in the provided Java code, so it's left as a placeholder.
```

Please note that this translation does not include all classes and methods from your original Java code. The `ConflictInfo`, `ProgramMultiUserMergeManager`, `ConflictCountPanel`, `ConflictPanel`, `BorderLayout`, `EmptyBorder` and `ChangeListener` are placeholders for the missing parts of your code, as they were not provided in the given translation task.