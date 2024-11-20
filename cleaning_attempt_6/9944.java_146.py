from abc import ABC, abstractmethod


class MagePanel(ABC):
    @abstractmethod
    def add_dependencies(self, state: 'WizardState') -> None:
        pass

    @abstractmethod
    def get_panel_displayability_and_update_state(self, state: 'WizardState') -> int:
        pass

    @abstractmethod
    def enter_panel(self, state: 'WizardState') -> None:
        pass

    @abstractmethod
    def leave_panel(self, state: 'WizardState') -> None:
        pass

    @abstractmethod
    def update_state_object_with_panel_info(self, state: 'WizardState') -> None:
        pass

    @abstractmethod
    def dispose(self) -> None:
        pass


class WizardPanelDisplayability(int):
    pass
