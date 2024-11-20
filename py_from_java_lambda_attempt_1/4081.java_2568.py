Here is the translation of the Java code into Python:

```Python
class NavigationHistoryPlugin:
    def __init__(self):
        self.history_list_map = {}
        self.max_history_size = 30

    @property
    def max_history_size(self):
        return self._max_history_size

    @max_history_size.setter
    def max_history_size(self, value):
        if not isinstance(value, int) or value < 10:
            raise OptionsVetoException("History size cannot be less than 10")
        elif value > 100:
            raise OptionsVetoException("History size cannot be greater than 100")
        self._max_history_size = value

    def read_data_state(self):
        pass

    def data_state_restore_completed(self, save_state=None):
        if not isinstance(save_state, SaveState) or save_state is None:
            return
        program_manager = ProgramManager()
        programs = program_manager.get_all_open_programs()
        count = save_state.get_int("LIST_COUNT", 0)
        for i in range(count):
            xml_element = save_state.get_xml_element(f"HISTORY_LIST_{i}")
            self.restore_history_list(xml_element, programs)

    def init_options(self):
        options = ToolOptions()
        options.register_option(
            "Max Navigation History Size",
            self.max_history_size,
            None,
            "The maximum number of items to display in the tool's navigation history."
        )
        self.max_history_size = options.get_int("Max Navigation History Size", 30)
        options.add_optionsChangeListener(self)

    def process_event(self, event):
        if isinstance(event, ProgramClosedPluginEvent):
            program = event.get_program()
            for navigatable in list(self.history_list_map.keys()):
                if navigatable.is_connected():
                    self.clear(navigatable)
                else:
                    go_to_service = GoToService()
                    default_navigatable = go_to_service.get_default_navigatable()
                    if default_navigatable is not None and default_navigatable == navigatable:
                        break
            return

    def add_new_location(self, navigatable):
        history_list = self.history_list_map.get(navigatable)
        if history_list is None or len(history_list) >= self.max_history_size:
            location_memento = navigatable.get_memento()
            if location_memento.is_valid():
                history_list.append(location_memento)

    def clear(self, program):
        for key in list(self.history_list_map.keys()):
            if key.is_connected() and key == program:
                break
        else:
            return

        self.notify_history_change()

    def notify_history_change(self):
        pass

class HistoryList:
    def __init__(self, max_locations=30):
        self.list = []
        self.current_location = 0
        self.max_locations = max_locations

    @property
    def current_location_index(self):
        return self._current_location

    @current_location_index.setter
    def current_location_index(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Current location index must be a non-negative integer")
        elif value >= len(self.list):
            raise IndexError("Index out of range")
        self._current_location = value

    @property
    def max_locations(self):
        return self._max_locations

    @max_locations.setter
    def max_locations(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Max locations must be a non-negative integer")
        elif value > 100:
            raise OptionsVetoException("History size cannot be greater than 100")
        self._max_locations = value

    def add_location(self, location):
        if len(self.list) >= self.max_locations:
            self.list.pop(0)
        self.list.append(location)

    def get_current_location_index(self):
        return self.current_location_index

    def set_max_locations(self, max_locations):
        self.max_locations = max_locations
        for i in range(len(self.list)):
            if len(self.list) > self.max_locations:
                self.list.pop(0)
                break

    def remove(self, location):
        try:
            index = self.list.index(location)
            del self.list[index]
            if self.current_location_index >= 1 and self.current_location_index == index + 1:
                self.current_location_index -= 1
        except ValueError:
            pass

class LocationMemento:
    def __init__(self, program_location):
        self.program = program_location.get_program()
        self.address = program_location.get_address()

    @property
    def is_valid(self):
        return True

    @is_valid.setter
    def is_valid(self, value):
        if not isinstance(value, bool):
            raise ValueError("Invalid value for 'valid' property")
        self._is_valid = value

class ProgramLocation:
    def __init__(self, program, address):
        self.program = program
        self.address = address

class NavigatableRegistry:
    @staticmethod
    def get_navigatable(instance_id):
        pass

class GoToService:
    @staticmethod
    def get_default_navigatable():
        return None

class ProgramManager:
    def __init__(self):
        pass

    def get_all_open_programs(self):
        return []

    def is_connected(self, program):
        return False