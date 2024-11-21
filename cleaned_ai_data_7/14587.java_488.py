class NazgulEnumTest:
    def test_the_same_object_is_returned_with_multiple_calls(self):
        for nazgul_enum in [NazgulEnum.VALUE1, NazgulEnum.VALUE2]:
            instance1 = nazgul_enum
            instance2 = nazgul_enum
            instance3 = nazgul_enum
            self.assertEqual(instance1, instance2)
            self.assertEqual(instance1, instance3)
            self.assertEqual(instance2, instance3)

class NazgulEnum:
    VALUE1 = None
    VALUE2 = None

    def __new__(cls, value):
        if not hasattr(cls, 'instances'):
            cls.instances = {}
        if value not in cls.instances:
            if value == NazgulEnum.VALUE1:
                instance = super(NazgulEnum, cls).__new__(cls)
                instance.value = 1
            elif value == NazgulEnum.VALUE2:
                instance = super(NazgulEnum, cls).__new__(cls)
                instance.value = 2
            else:
                raise ValueError(f"Invalid value: {value}")
            cls.instances[value] = instance
        return cls.instances[value]
