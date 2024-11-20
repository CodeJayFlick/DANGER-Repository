class PreferenceState:
    PREFERENCE_STATE_NAME = "PREFERENCE_STATE"

    def __init__(self):
        super().__init__(PREFERENCE_STATE_NAME)

    @classmethod
    def from_element(cls, element):
        return cls(element)
