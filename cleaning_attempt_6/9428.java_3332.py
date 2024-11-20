from abc import ABCMeta, abstractmethod
import tkinter as tk


class MultiStateDockingAction(metaclass=ABCMeta):
    def __init__(self, name: str, owner: str) -> None:
        self.name = name
        self.owner = owner

    @abstractmethod
    def action_state_changed(self, new_action_state: 'ActionState', trigger: int) -> None:

class ActionContext:
    pass


class DockingWindowManager:
    active_instance = None

def get_active_docking_window_manager() -> 'DockingWindowManager':
    return DockingWindowManager.active_instance


class EmptyIcon:
    def __init__(self, width: int, height: int) -> None:
        self.width = width
        self.height = height

    @property
    def icon(self):
        pass  # This is a placeholder for the actual icon


class MultipleActionDockingToolbarButton:
    def __init__(self, multi_action_generator: callable) -> None:
        self.multi_action_generator = multi_action_generator

    def set_perform_action_on_button_click(self, perform_action: bool) -> None:
        pass  # This is a placeholder for the actual method implementation


class ActionState(metaclass=ABCMeta):
    @abstractmethod
    def get_icon(self) -> 'Icon':
        pass

    @property
    def user_data(self):
        pass  # This is a placeholder for the actual data


class ToggleDockingAction:
    def __init__(self, action_state: 'ActionState', selected: bool = False) -> None:
        self.action_state = action_state
        self.selected = selected

    @property
    def icon(self):
        pass  # This is a placeholder for the actual icon


class DockingAction(metaclass=ABCMeta):
    @abstractmethod
    def do_create_button(self) -> 'MultipleActionDockingToolbarButton':
        pass

    @abstractmethod
    def set_menu_bar_data(self, new_menu_data: dict) -> None:
        pass

    @abstractmethod
    def set_popup_menu_data(self, new_menu_data: dict) -> None:
        pass


class MultiStateDockingActionIf(metaclass=ABCMeta):
    @abstractmethod
    def get_state_actions(self) -> list['ActionState']:
        pass


def main():
    # Create an instance of the DockingWindowManager.
    docking_window_manager = DockingWindowManager()
    DockingWindowManager.active_instance = docking_window_manager

    # Create a new MultiStateDockingAction and set its name, owner, and perform action on primary button click.
    multi_state_docking_action = MultiStateDockingAction("My Action", "Owner")
    multi_state_docking_action.set_perform_action_on_primary_button_click(True)

    # Add some state actions to the multi-state docking action.
    for i in range(5):
        action_state = ActionState()
        action_state.user_data = f"User Data {i}"
        multi_state_docking_action.add_action_state(action_state)


if __name__ == "__main__":
    main()

