class RespawnLocation:
    def __init__(self):
        self.parser = None  # This should be set when you create an instance of this class.

    @property
    def parser(self):
        return self._parser

    @parser.setter
    def parser(self, value):
        if not isinstance(value, object):  # Check that the parser is a valid Python object.
            raise TypeError("Parser must be a valid Python object.")
        self._parser = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not self.parser.is_current_event(PlayerRespawnEvent):  # This should check for PlayerRespawnEvent
            print("The expression 'respawn location' may only be used in the respawn event")
            return False

        return True

    def get(self, event):
        if isinstance(event, PlayerRespawnEvent):
            return [event.get_respawn_location()]
        else:
            return []

    @property
    def is_single(self):
        return True  # This should always be true.

    @is_single.setter
    def is_single(self, value):
        pass

    @property
    def get_return_type(self):
        return Location  # This should return the type of location.

    @get_return_type.setter
    def get_return_type(self, value):
        self._return_type = value

    def __str__(self, event=None, debug=False):
        if event is None:
            return "the respawn location"
        else:
            return f"the respawn location: {event.get_respawn_location()}"

    @property
    def accept_change(self):
        return [Location]  # This should be the type of change that can be accepted.

    @accept_change.setter
    def accept_change(self, value):
        pass

    def change(self, event, delta=None, mode=ChangeMode.SET):
        if delta is not None:
            event.set_respawn_location(delta[0])
