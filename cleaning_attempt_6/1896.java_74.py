class TypeSummaryCapping:
    _swig_values = [eTypeSummaryCapped, eTypeSummaryUncapped]
    _swig_next = 0

    def __init__(self, swig_name):
        self.swig_name = swig_name
        global _swig_next
        self.swig_value = _swig_next
        _swig_next += 1

    @classmethod
    def eTypeSummaryCapped(cls):
        return cls("eTypeSummaryCapped", lldbJNI.eTypeSummaryCapped_get())

    @classmethod
    def eTypeSummaryUncapped(cls):
        return cls("eTypeSummaryUncapped", lldbJNI.eTypeSummaryUncapped_get())

    def swig_value(self):
        return self.swig_value

    def __str__(self):
        return self.swig_name

    @classmethod
    def swig_to_enum(cls, swig_value):
        if 0 <= swig_value < len(cls._swig_values) and cls._swig_values[swig_value].swig_value == swig_value:
            return cls._swig_values[swig_value]
        for i in range(len(cls._swig_values)):
            if cls._swig_values[i].swig_value == swig_value:
                return cls._swig_values[i]
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    @classmethod
    def __new__(cls, *args):
        if len(args) > 0 and isinstance(args[0], str):
            instance = super().__new__(cls)
            instance.swig_name = args[0]
            global _swig_next
            instance.swig_value = _swig_next
            _swig_next += 1
            return instance
        elif len(args) > 0 and isinstance(args[0], int):
            instance = super().__new__(cls)
            instance.swig_name = args[1]
            instance.swig_value = args[0]
            global _swig_next
            _swig_next = instance.swig_value + 1
            return instance
        elif len(args) > 0 and isinstance(args[0], TypeSummaryCapping):
            instance = super().__new__(cls)
            instance.swig_name = args[1]
            instance.swig_value = args[0].swig_value
            global _swig_next
            _swig_next = instance.swig_value + 1
            return instance

    @classmethod
    def __init_subclass__(cls, name):
        pass


eTypeSummaryCapped = TypeSummaryCapping.eTypeSummaryCapped()
eTypeSummaryUncapped = TypeSummaryCapping.eTypeSummaryUncapped()

lldbJNI = None
