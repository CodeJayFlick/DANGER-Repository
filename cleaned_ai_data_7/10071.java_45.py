import serializable

class AnonymousCallback(serializable.Serializable):
    serialVersionUID = 1L

    def __init__(self):
        self.anonymous_access_requested = False

    def set_anonymous_access_requested(self, state: bool) -> None:
        self.anonymous_access_requested = state

    def anonymous_access_requested(self) -> bool:
        return self.anonymous_access_requested
