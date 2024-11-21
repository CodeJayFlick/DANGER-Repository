class ActionBuilder:
    def __init__(self, name: str, owner: str):
        super().__init__(name, owner)

    def self(self) -> 'ActionBuilder':
        return self

    def build(self) -> DockingAction:
        self.validate()
        action = DockingAction(name=self.name, owner=owner)
        action.actionPerformed = lambda context: self.actionCallback.accept(context)
        self.decorate_action(action)
        return action
