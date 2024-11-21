from abc import ABC, abstractmethod
import tkinter as tk
from typing import List, Tuple

class PreconditionsPanel(ABC):
    def __init__(self, panel_manager: 'VTNewSessionWizardManager'):
        self.panel_manager = panel_manager
        self.conditions_test_panel = None
        self.tests_done = False

    @abstractmethod
    def get_help_location(self) -> str:
        pass

    @abstractmethod
    def add_dependencies(self, state):
        pass

    @abstractmethod
    def dispose(self):
        if self.conditions_test_panel is not None:
            self.conditions_test_panel.cancel()

    @abstractmethod
    def enter_panel(self, state):
        self.initialize_run_state(state)
        if not self.tests_done:
            if self.conditions_test_panel is not None:
                self.remove(self.conditions_test_panel)
            self.conditions_test_panel = self.build_condition_panel(state)
            self.add(self.conditions_test_panel)

    def initialize_run_state(self, state) -> None:
        b = state.get(VTWizardStateKey.PRECONDITION_CHECKS_RUN)
        self.tests_done = b is None or not bool(b)

    def build_condition_panel(self, state: 'WizardState[VTWizardStateKey]') -> 'ConditionTestPanel':
        source_program = state.get(VTZizardStateKey.SOURCE_PROGRAM)
        destination_program = state.get(VTZizardStateKey.DESTINATION_PROGRAM)
        existing_results = state.get(VTZizardStateKey.EXISTING_SESSION)

        list_ = self.get_condition_tests(source_program, destination_program, existing_results)
        panel = ConditionTestPanel(list_)
        return panel

    def get_condition_tests(self, source_program: 'Program', 
                             destination_program: 'Program',
                             existing_results: 'VTSession') -> List['ConditionTester']:
        list_ = []
        for validator_class in ClassSearcher.get_classes(VTPreconditionValidator):
            try:
                ctor = validator_class.__init__(source_program, destination_program, existing_results)
                validator = ctor()
                list_.append(validator)
            except Exception as e:
                print(f"Error including VTPreconditionValidator {validator_class}: {e}")
        return list_

    @abstractmethod
    def get_panel_displayability_and_update_state(self, state: 'WizardState[VTWizardStateKey]') -> int:
        pass

    @abstractmethod
    def leave_panel(self, state):
        self.update_state_object_with_panel_info(state)

    def update_state_object_with_panel_info(self, state) -> None:
        state.put(VTZizardStateKey.PRECONDITION_CHECKS_RUN, bool(self.tests_done))
        state.put(VTZizardStateKey.HIGHEST_PRECONDITION_STATUS, self.has_any_error_status())

    @abstractmethod
    def has_any_error_status(self) -> bool:
        pass

    @abstractmethod
    def get_title(self):
        return "Precondition Checklist"

    @abstractmethod
    def initialize(self):
        # do nothing
        pass

    @abstractmethod
    def is_valid_information(self) -> bool:
        return self.tests_done

    @abstractmethod
    def get_preferred_size(self) -> Tuple[int, int]:
        super_size = super().get_preferred_size()
        if (super_size[0] > DEFAULT_SIZE.width and 
            super_size[1] > DEFAULT_SIZE.height):
            return super_size
        else:
            return DEFAULT_SIZE

    @abstractmethod
    def get_preferred_scrollable_viewport_size(self) -> Tuple[int, int]:
        return self.get_preferred_size()

    @abstractmethod
    def get_scrollable_block_increment(self, visible_rect: 'Rectangle', 
                                        orientation: int, direction: int):
        return 25

    @abstractmethod
    def get_scrollable_tracks_viewport_height(self) -> bool:
        return True

    @abstractmethod
    def get_scrollable_tracks_viewport_width(self) -> bool:
        return True

    @abstractmethod
    def get_scrollable_unit_increment(self, visible_rect: 'Rectangle', 
                                       orientation: int, direction: int):
        return 10


class ConditionTestPanel(ABC):
    def __init__(self, list_: List['ConditionTester']):
        self.list_ = list_

    @abstractmethod
    def run_tests(self) -> None:
        pass

    @abstractmethod
    def skip_tests(self) -> None:
        pass

    @abstractmethod
    def get_error_count(self) -> int:
        pass


class WizardStateKey(ABC):
    PRECONDITION_CHECKS_RUN = 'precondition_checks_run'
    SOURCE_PROGRAM = 'source_program'
    DESTINATION_PROGRAM = 'destination_program'
    EXISTING_SESSION = 'existing_session'

    HIGHEST_PRECONDITION_STATUS = 'highest_precondition_status'


class VTNewSessionWizardManager:
    def __init__(self):
        pass

    @abstractmethod
    def get_wizard_manager(self) -> None:
        pass


class Program(ABC):
    pass


class ConditionTester(ABC):
    NAME = "name"

    @abstractmethod
    def get_name(self) -> str:
        pass


class VTPreconditionValidator(ABC):
    pass

DEFAULT_SIZE = (650, 480)
