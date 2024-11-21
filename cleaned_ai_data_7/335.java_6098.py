class TracePcodeUtils:
    @staticmethod
    def executor_for_coordinates(coordinates):
        trace = coordinates.get_trace()
        if trace is None:
            raise ValueError("Coordinates have no trace")
        
        language = trace.get_base_language()
        if not isinstance(language, SleighLanguage):
            raise ValueError("Given trace does not use a Sleigh language")

        slang = language
        state = TracePcodeState(coordinates)
        return AsyncPcodeExecutor(slang, AsyncWrappedArithmetic.for_language(slang), state)


class AsyncPcodeExecutor:
    def __init__(self, slang, arithmetic, state):
        self.slang = slang
        self.arithmetic = arithmetic
        self.state = state


class TracePcodeState:
    def __init__(self, coordinates):
        if coordinates.get_recorder() is None:
            self.__wrapped_state = WrappedPcodeExecutorState(
                TraceBytesPcodeExecutorState(coordinates.get_trace(), 
                                             coordinates.get_view_snap(),
                                             coordinates.get_thread(),
                                             coordinates.get_frame()))
        else:
            self.__wrapped_state = RecorderWrappedPcodeExecutorState(
                coordinates.get_recorder(), 
                coordinates.get_snap(), 
                coordinates.get_thread(), 
                coordinates.get_frame())


class WrappedPcodeExecutorState:
    def __init__(self, state):
        self.state = state


class AsyncWrappedArithmetic:
    @staticmethod
    def for_language(slang):
        # This method should be implemented based on the given SleighLanguage.
        pass

