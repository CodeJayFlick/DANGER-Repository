class JdiModelTargetElementsContainer:
    def __init__(self, parent: 'JdiModelTargetObject', name):
        super().__init__(parent, name)

    @property
    def thread_groups_by_id(self) -> dict:
        return {}

    def add_elements(self, els: list):
        self.set_elements(els, {}, "Initialized")

class JdiEventsListenerAdapter:
    pass

class TargetElementType(type):
    pass

class TargetAttributeType(type):
    pass

class ResyncMode:
    ONCE = None
