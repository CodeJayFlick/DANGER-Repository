class PaperBrigadier:
    def __init__(self):
        raise RuntimeError("PaperBrigadier cannot be instantiated!")

    @staticmethod
    def message(component_like: 'ComponentLike') -> Message:
        return PaperBrigadierProvider.instance().message(component_like)

    @staticmethod
    def component_from_message(message: Message) -> Component:
        return PaperBrigadierProvider.instance().component_from_message(message)
