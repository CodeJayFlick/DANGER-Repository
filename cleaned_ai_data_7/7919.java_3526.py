class MDTypeInfo:
    PRIVATE = "private: "
    PROTECTED = "protected: "
    PUBLIC = "public: "
    STATIC = "static "
    VIRTUAL = "virtual "
    THUNK = "[thunk]:"
    EXTERNC = "extern \"C\" "

    class AccessSpecifier:
        NOT_SPECIFIED = 0
        PRIVATE = 1
        PROTECTED = 2
        PUBLIC = 3

    class StorageClass:
        NOT_SPECIFIED = 0
        STATIC = 1
        VIRTUAL = 2

    def __init__(self, dmang):
        self.storage = MDTypeInfo.StorageClass.NOT_SPECIFIED
        self.access = MDTypeInfo.AccessSpecifier.NOT_SPECIFIED
        self.is_thunk = False
        self.is_member = True
        self.is_extern_c = False
        self.special_handling_code = '\0'
        self.mdtype = None
        self.is_type_cast = False

    def get_name_modifier(self):
        return ""

    def set_private(self):
        self.access = MDTypeInfo.AccessSpecifier.PRIVATE

    def is_private(self):
        return self.access == MDTypeInfo.AccessSpecifier.PRIVATE

    def set_protected(self):
        self.access = MDTypeInfo.AccessSpecifier.PROTECTED

    def is_protected(self):
        return self.access == MDTypeInfo.AccessSpecifier.PROTECTED

    def set_public(self):
        self.access = MDTypeInfo.AccessSpecifier.PUBLIC

    def is_public(self):
        return self.access == MDTypeInfo.AccessServletRequest.ACCESS_SPECIFIER_PUBLIC

    def set_static(self):
        self.storage = MDTypeInfo.StorageClass.STATIC

    def is_static(self):
        return self.storage == MDTypeInfo.StorageClass.STATIC

    def set_virtual(self):
        self.storage = MDTypeInfo.StorageClass.VIRTUAL

    def is_virtual(self):
        return self.storage == MDTypeInfo.StorageClass.VIRTUAL

    def set_thunk(self):
        self.is_thunk = True

    def is_thunk(self):
        return self.is_thunk

    def set_extern_c(self):
        self.is_extern_c = True

    def is_extern_c(self):
        return self.is_extern_c

    def set_special_handling_code(self, code):
        self.special_handling_code = code

    def get_special_handling_code(self):
        return self.special_handling_code

    def set_non_member(self):
        self.is_member = False

    def is_member(self):
        return self.is_member

    def set_type_cast(self):
        self.is_type_cast = True

    def get_mdtype(self):
        return self.mdtype

    def insert(self, builder):
        if self.mdtype:
            self.mdtype.insert(builder)
        self.insert_access_modifiers(builder)

    def insert_access_modifiers(self, builder):
        modifiers_builder = ""
        if self.storage != MDTypeInfo.StorageClass.NOT_SPECIFIED:
            if self.storage == MDTypeInfo.StorageClass.STATIC:
                modifiers_builder += "static "
            elif self.storage == MDTypeInfo.StorageClass.VIRTUAL:
                modifiers_builder += "virtual "

        if self.access != MDTypeInfo.AccessSpecifier.NOT_SPECIFIED:
            if self.access == MDTypeInfo.AccessSpecifier.PRIVATE:
                modifiers_builder += "private: "
            elif self.access == MDTypeInfo.AccessSpecifier.PROTECTED:
                modifiers_builder += "protected: "
            elif self.access == MDTypeInfo.AccessSpecifier.PUBLIC:
                modifiers_builder += "public: "

        if self.is_thunk:
            modifiers_builder += "[thunk]:"
        if self.is_extern_c:
            modifiers_builder += "extern \"C\""

        builder.insert(modifiers_builder)

    def parse_internal(self):
        if self.mdtype:
            self.mdtype.parse()
