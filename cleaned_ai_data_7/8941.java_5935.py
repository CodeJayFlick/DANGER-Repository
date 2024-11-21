class Filter:
    def __init__(self):
        self.listeners = set()

    def passes_filter(self, item):
        pass  # abstract method, needs implementation in subclass

    def get_filter_status(self):
        pass  # abstract method, needs implementation in subclass

    def clear_filter(self):
        pass  # abstract method, needs implementation in subclass

    def get_component(self):
        pass  # abstract method, needs implementation in subclass

    def dispose(self):
        self.listeners.clear()

    def add_listener(self, listener):
        self.listeners.add(listener)

    def fire_status_changed(self, status):
        for listener in self.listeners:
            listener.filter_status_changed(status)

    class FilterEditingStatus(enum.Enum):
        NONE = ("", None)
        DIRTY = ("Filter contents have changed, but are not yet applied",
                 "images/bullet_black.png")
        ERROR = ("Filter contents are not valid", "images/no_small.png")
        APPLIED = ("Filter applied", "images/bullet_green.png")

    class FilterShortcutState(enum.Enum):
        ALWAYS_PASSES
        REQUIRES_CHECK
        NEVER_PASSES

    def create_copy(self):
        copy = self.create_empty_copy()
        ss = SaveState()
        self.write_config_state(ss)
        copy.read_config_state(ss)
        return copy

    def create_empty_copy(self):
        # Note: for this code to work, each subclass must have a no-arg, public constructor.
        clazz = type(self)
        try:
            constructor = clazz.__init__
            newInstance = constructor()
            return self
        except Exception as e:
            raise AssertionError(f"Exception copying filter '{clazz.__name__}'--missing empty constructor?", e)

    def read_config_state(self, save_state):
        pass  # abstract method, needs implementation in subclass

    def write_config_state(self, save_state):
        pass  # abstract method, needs implementation in subclass
