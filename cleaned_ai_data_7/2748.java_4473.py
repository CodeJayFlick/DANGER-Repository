class PcodeStateInitializer:
    def __init__(self):
        pass

    def is_applicable(self, language: str) -> bool:
        # TO DO: implement annotation-based check
        return True  # default implementation

    def initialize_machine(self, machine_state: object) -> None:
        pass  # no-op by default

    def initialize_thread(self, thread_state: object) -> None:
        pass  # no-op by default


class ExtensionPoint(PcodeStateInitializer):
    pass
