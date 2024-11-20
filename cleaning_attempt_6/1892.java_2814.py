class TraceType:
    eTraceTypeNone = None
    eTraceTypeProcessorTrace = None

    def __init__(self, name):
        self.name = name
        global next_value
        if not hasattr(TraceType, 'next_value'):
            TraceType.next_value = 0
        self.value = TraceType.next_value
        TraceType.next_value += 1

    @classmethod
    def swig_to_enum(cls, value):
        for enum in cls.__dict__.values():
            if isinstance(enum, TraceType) and enum.value == value:
                return enum
        raise ValueError(f"No enum {cls.__name__} with value {value}")

    def __str__(self):
        return self.name

    @property
    def swig_value(self):
        return self.value


# Initialize the enums
TraceType.eTraceTypeNone = TraceType("eTraceTypeNone")
TraceType.eTraceTypeProcessorTrace = TraceType("eTraceTypeProcessorTrace")

swig_values = [TraceType.eTraceTypeNone, TraceType.eTraceTypeProcessorTrace]
