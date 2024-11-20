class DbgStateListener:
    def __init__(self):
        pass

    def state_changed(self, old_state: 'DbgState', new_state: 'DbgState', cause: 'DbgCause'):
        """The state has changed because of the given cause"""
        # Your code here to handle the state change
        pass


class DbgState:
    pass


class DbgCause:
    pass

