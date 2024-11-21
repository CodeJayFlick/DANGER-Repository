Here is the translation of the Java code into Python:

```Python
class MDDataTypeParser:
    def parse_data_type(self, dmang: object, is_highest: bool) -> object:
        dt = None
        code = dmang.peek()
        
        if code == '?':
            dmang.increment()
            dt = self.parse_modifier_type(dmang)
        elif code == 'X':
            dmang.increment()
            dt = self.parse_void_data_type(dmang)
        else:
            dt = self.parse_primary_data_type(dmang, is_highest)

        return dt

    def parse_primary_data_type(self, dmang: object, is_highest: bool) -> object:
        dt = None
        code = dmang.peek()
        
        if code == '$':
            dmang.increment()
            dt = self.parse_special_extended_type(dmang, is_highest)
        elif code in ['A', 'B']:
            dmang.increment()
            rt = self.parse_reference_type(dmang)
            dt = rt
            
            if is_highest and code == 'B':
                rt.clear_const()
                rt.set_volatile()
            else:
                rt.clear_const()
                rt.clear_volitile()
        else:
            dt = self.parse_basic_data_type(dmang, is_highest)

        return dt

    def parse_special_extended_type(self, dmang: object, is_highest: bool) -> object:
        dt = None
        code = dmang.get_and_increment()

        if code != '$':
            raise MDException("ExtendedType invalid character: " + str(code))

        code = dmang.get_and_increment()
        
        switcher = {
            'A': lambda: self.parse_function_indirect_type(dmang),
            'B': lambda: self.parse_pointer_ref_data_type(dmang),
            'C': lambda: self.parse_data_reference_type(dmang),
            'Q': lambda: self.parse_data_ref_ref_type(dmang, is_highest),
            'R': lambda: self.parse_std_null_ptr_type(dmang)
        }
        
        func = switcher.get(code.upper())
        if func:
            dt = func()
        else:
            raise MDException("TemplateParameterModifierType unrecognized code: " + str(code))

        return dt

    def parse_basic_data_type(self, dmang: object, is_highest: bool) -> object:
        dt = None
        code = dmang.get_and_increment()

        switcher = {
            'C': lambda: self.parse_char_data_type(dmang),
            'D': lambda: self.parse_short_data_type(dmang),
            'E': lambda: self.parse_unsigned_short_data_type(dmang),
            'F': lambda: self.parse_int8_data_type(dmang, is_highest),
            'G': lambda: self.parse_uint16_data_type(dmang, is_highest),
            'H': lambda: self.parse_int32_data_type(dmang, is_highest),
            'I': lambda: self.parse_uint64_data_type(dmang, is_highest),
            'J': lambda: self.parse_long_data_type(dmang, is_highest),
            'K': lambda: self.parse_ulonglong_data_type(dmang, is_highest),
            'L': lambda: self.parse_complex_type dmang,
            'M': lambda: self.parse_float_data_type(dmang),
            'N': lambda: self.parse_double_data_type(dmang),
            'O': lambda: self.parse_longdouble_data_type(dmang)
        }
        
        func = switcher.get(code.upper())
        if func:
            dt = func()
        else:
            raise MDException("Type code not expected: " + str(code))

        return dt

    def parse_modifier_type(self, dmang: object) -> object:
        # implementation
        pass

    def parse_void_data_type(self, dmang: object) -> object:
        # implementation
        pass

    def parse_function_indirect_type(self, dmang: object) -> object:
        # implementation
        pass

    def parse_pointer_ref_data_type(self, dmang: object) -> object:
        # implementation
        pass

    def parse_data_reference_type(self, dmang: object) -> object:
        # implementation
        pass

    def parse_data_ref_ref_type(self, dmang: object, is_highest: bool) -> object:
        # implementation
        pass

    def parse_std_null_ptr_type(self, dmang: object) -> object:
        # implementation
        pass

    def parse_char_data_type(self, dmang: object) -> object:
        # implementation
        pass

    def parse_short_data_type(self, dmang: object) -> object:
        # implementation
        pass

    def parse_unsigned_short_data_type(self, dmang: object) -> object:
        # implementation
        pass

    def parse_int8_data_type(self, dmang: object, is_highest: bool) -> object:
        # implementation
        pass

    def parse_uint16_data_type(self, dmang: object, is_highest: bool) -> object:
        # implementation
        pass

    def parse_int32_data_type(self, dmang: object, is_highest: bool) -> object:
        # implementation
        pass

    def parse_ulonglong_data_type(self, dmang: object, is_highest: bool) -> object:
        # implementation
        pass

    def parse_long_data_type(self, dmang: object, is_highest: bool) -> object:
        # implementation
        pass

    def parse_float_data_type(self, dmang: object) -> object:
        # implementation
        pass

    def parse_double_data_type(self, dmang: object) -> object:
        # implementation
        pass

    def parse_longdouble_data_type(self, dmang: object) -> object:
        # implementation
        pass