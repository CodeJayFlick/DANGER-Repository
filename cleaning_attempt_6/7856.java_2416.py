class MDModifierType:
    SPACE = ' '
    CONST = "const"
    VOLATILE = "volatile"

    def __init__(self):
        self.is_const = False
        self.is_volatile = False
        self.managed_property = None
        self.cv_mod = None
        self.has_cv_mod = True
        self.ref_type = None

    def set_const(self):
        self.is_const = True

    def clear_const(self):
        self.is_const = False

    def is_const(self):
        return self.is_const

    def set_volatile(self):
        self.is_volatile = True

    def clear_volatile(self):
        self.is_volatile = False

    def is_volatile(self):
        return self.is_volatile

    def is_pointer64(self):
        if hasattr(self.cv_mod, 'is_pointer_64'):
            return self.cv_mod.is_pointer_64()
        else:
            return None

    def is_restrict(self):
        if hasattr(self.cv_mod, 'is_restricted'):
            return self.cv_mod.is_restricted()
        else:
            return None

    def is_unaligned(self):
        if hasattr(self.cv_mod, 'is_unaligned'):
            return self.cv_mod.is_unaligned()
        else:
            return None

    def get_based_name(self):
        if hasattr(self.cv_mod, 'get_based_name'):
            return self.cv_mod.get_based_name()
        else:
            return None

    def get_member_scope(self):
        if hasattr(self.cv_mod, 'get_member_scope'):
            return self.cv_mod.get_member_scope()
        else:
            return None

    def parse_referenced_type(self) -> MDDataType:
        # 20170418 dmang.push_modifier_context();
        cv_mod.parse()
        ref_type = MDDataTypeParser().parse_primary_data_type(False)
        if hasattr(ref_type, 'set_is_referenced_type'):
            ref_type.set_is_referenced_type()
        return ref_type

    def parse_array_property(self) -> None:
        pass  # This method is not implemented in Python.

    @staticmethod
    def set_array_string(array_string: str):
        array_string = Objects.requireNonNull(array_string)
        MDModifierType.array_string = array_string

    @property
    def array_string(self):
        return self.__array_string

    def insert_cv_mod(self, builder) -> None:
        cv_mod.insert(builder)

    def insert_array_string(self, builder) -> None:
        if not self.array_string.empty():
            dmang.append_string(builder, "(")
            dmang.append_string(builder, ")")
            dmang.append_string(builder, self.array_string)

    def insert_referred_type(self, builder):
        ref_type.insert(builder)

    @staticmethod
    def insert(builder) -> None:
        if not cv_mod.is_cli_array():
            if is_volatile:
                dmang.insert_spaced_string(builder, MDModifierType.VOLATILE)
            if is_const:
                dmang.insert_spaced_string(builder, MDModifierType.CONST)
        else:
            ref_type = MDArrayReferencedType()
            insert_referred_type(ref_type)
            dmang.append_string(builder, ref_type)

    def __init__(self):
        super().__init__()
