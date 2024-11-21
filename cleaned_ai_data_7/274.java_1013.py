class ManagedStackRecorder:
    def offer_stack_frame(self, added):
        pass  # implement this method in your subclass

    def record_stack(self):
        pass  # implement this method in your subclass

    def get_successor_frame_level(self, successor: int) -> int:
        raise NotImplementedError("Method not implemented")

    def get_trace_stack_frame(self, trace_thread: object, level: int) -> object:
        raise NotImplementedError("Method not implemented")

    def get_target_stack_frame(self, frame_level: int) -> object:
        raise NotImplementedError("Method not implemented")
