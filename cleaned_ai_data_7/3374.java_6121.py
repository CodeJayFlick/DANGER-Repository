class LocationMemento:
    PROGRAM_PATH = "PROGRAM_PATH"
    PROGRAM_ID = "PROGRAM_ID"
    MEMENTO_CLASS = "MEMENTO_CLASS"

    def __init__(self, program: 'Program', location: 'ProgramLocation'):
        self.program = program
        self.program_location = location

    @classmethod
    def from_save_state(cls, save_state: dict, programs: list):
        program_path = save_state.get(PROGRAM_PATH)
        program_id = save_state.get(PROGRAM_ID)

        if not (program_path and isinstance(program_id, int)):
            raise ValueError("Invalid SaveState")

        for p in programs:
            if p.unique_program_id == program_id:
                program = p
                break

        else:
            raise ValueError(f"Program with ID {program_id} not found")

        return cls(program=program, location=save_state.get_location())

    def is_valid(self):
        return self.program and self.program_location

    @property
    def location_description(self):
        return str(self.program_location.address)

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value):
        if not isinstance(value, 'Program'):
            raise ValueError("Invalid Program")
        self._program = value

    @property
    def program_location(self):
        return self._program_location

    @program_location.setter
    def program_location(self, value):
        if not isinstance(value, 'ProgramLocation'):
            raise ValueError("Invalid Location")
        self._program_location = value

    def __eq__(self, other):
        if id(self) == id(other):
            return True
        elif not isinstance(other, LocationMemento):
            return False
        else:
            return (id(self.program) == id(other.program) and 
                    compare_locations(self.program_location, other.program_location))

    def __hash__(self):
        prime = 31
        result = 1

        result = prime * result + hash(self.program)

        if not isinstance(self.program_location, 'AddressFieldLocation'):
            result += hash(type(self.program_location))
        else:
            result += hash(self.program_location.address)
        return result

    def __str__(self):
        return f"LocationMemento[location={self.program_location}]"

def compare_locations(loc1: 'ProgramLocation', loc2: 'ProgramLocation') -> bool:
    if not (loc1 and loc2):
        return False
    elif id(loc1) == id(loc2):
        return True

    if loc1.address != loc2.address:
        return False

    if type(loc1) is type(loc2):
        return True

    # at this point we know they have the same addresses, but different location types (fields)
    # also consider generic program locations to be equal to addressField locations
    return isinstance(loc1, 'AddressFieldLocation') and isinstance(loc2, 'AddressFieldLocation')

def save_state(self: 'LocationMemento', save_state: dict):
    save_state[MEMENTO_CLASS] = self.__class__.__name__
    save_state[PROGRAM_PATH] = str(self.program.domain_file)
    save_state[PROGRAM_ID] = self.program.unique_program_id
    self.program_location.save_state(save_state)

@staticmethod
def get_location_memento(save_state: dict, programs: list) -> 'LocationMemento':
    try:
        memento_class_name = save_state[MEMENTO_CLASS]
        if not memento_class_name:
            return None

        memento_class = globals()[memento_class_name]

        constructor = getattr(memento_class, "from_save_state")
        return constructor(save_state=save_state, programs=programs)
    except (KeyError, AttributeError):
        pass
