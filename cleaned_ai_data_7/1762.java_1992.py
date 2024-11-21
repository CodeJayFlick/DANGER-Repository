class InstrumentationRuntimeType:
    _values = [
        ("eInstrumentationRuntimeTypeAddressSanitizer", 0),
        ("eInstrumentationRuntimeTypeThreadSanitizer", 1),
        ("eInstrumentationRuntimeTypeUndefinedBehaviorSanitizer", 2),
        ("eInstrumentationRuntimeTypeMainThreadChecker", 3),
        ("eInstrumentationRuntimeTypeSwiftRuntimeReporting", 4),
        ("eNumInstrumentationRuntimeTypes", None)
    ]

    def __init__(self, name):
        self.name = name
        InstrumentationRuntimeType._next_value += 1

    @classmethod
    def swig_to_enum(cls, value):
        if not (0 <= value < len(cls._values)):
            raise ValueError(f"No enum {cls.__name__} with value {value}")
        return cls(*cls._values[value])

    @property
    def name(self):
        return self.name

    @property
    def swig_value(self):
        return InstrumentationRuntimeType._next_value - 1


InstrumentationRuntimeType._next_value = 0

e_InstrumentationRuntimeType_AddressSanitizer = InstrumentationRuntimeType("eInstrumentationRuntimeTypeAddressSanitizer")
e_InstrumentationRuntimeType_ThreadSanitizer = InstrumentationRuntimeType("eInstrumentationRuntimeTypeThreadSanitizer")
e_InstrumentationRuntimeType_UndefinedBehaviorSanitizer = InstrumentationRuntimeType("eInstrumentationRuntimeTypeUndefinedBehaviorSanitizer")
e_InstrumentationRuntimeType_MainThreadChecker = InstrumentationRuntimeType("eInstrumentationRuntimeTypeMainThreadChecker")
e_InstrumentationRuntimeType_SwiftRuntimeReporting = InstrumentationRuntimeType("eInstrumentationRuntimeTypeSwiftRuntimeReporting")

print(e_InstrumentationRuntimeType_AddressSanitizer.name)
