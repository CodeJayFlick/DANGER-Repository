class IDebugClient6:
    IID_IDEBUG_CLIENT6 = "fd28b4c5-498-c468-a28e-62cad2154eb3"

    class VTIndices6(enum):
        SET_EVENT_CONTEXT_CALLBACKS = 0

        @classmethod
        def start(cls, indices: 'VTIndices5') -> int:
            return len(list(indices)) + cls.SET_EVENT_CONTEXT_CALLBACKS

        def get_index(self) -> int:
            return self.value + IDebugClient6.VTIndices6.start(VTIndices5)

    def set_event_context_callbacks(self, callbacks):
        pass  # Assuming this is an abstract method
