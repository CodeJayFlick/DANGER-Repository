class ArrayStringable:
    def __init__(self):
        pass

    def has_string_value(self, settings: 'Settings') -> bool:
        """
        For cases where an array of this type exists, determines if a String value will be returned.
        
        @param settings the Settings object
        @return true if array of this type with the specified settings will return a String value
        """
        pass

    def get_array_string(self, buf: 'MemBuffer', settings: 'Settings', length: int) -> str:
        """
        For cases where an array of this type exists, get the array value as a String.
        
        When data corresponds to character data it should generally be expressed as a string. 
        A null value is returned if not supported or memory is uninitialized.

        @param buf data buffer
        @param settings data settings
        @param length length of array
        @return array value expressed as a string or None if data is not character data
        """
        if self.has_string_value(settings) and buf.is_initialized_memory():
            return str(self.get_array_string(buf, settings, length))
        else:
            return None

    def get_array_default_label_prefix(self, buf: 'MemBuffer', settings: 'Settings', len: int,
                                         options: 'DataTypeDisplayOptions') -> str:
        """
        For cases where an array of this type exists, get the appropriate string to use as the default label prefix for the array.

        @param buf memory buffer containing the bytes.
        @param settings the Settings object
        @param len the length of the data.
        @param options options for how to format the default label prefix.
        @return the default label prefix or None if none specified.
        """
        pass

    def get_array_default_offcut_label_prefix(self, buf: 'MemBuffer', settings: 'Settings', len: int,
                                               options: 'DataTypeDisplayOptions', offcut_length: int) -> str:
        """
        For cases where an array of this type exists, get the appropriate string to use as the default label prefix, taking into account 
        the fact that there exists a reference to the data that references offcutLength bytes into this type

        @param buf memory buffer containing the bytes.
        @param settings the Settings object
        @param len the length of the data.
        @param options options for how to format the default label prefix.
        @param offcut_length the length of the offcut label prefix.
        @return the default label prefix or None if none specified.
        """
        pass

    def get_array_stringable(dt: 'DataType') -> 'ArrayStringable':
        """
        Get the ArrayStringable for a specified data type. Not used on an Array DataType, but 
        on Array's element' types.

        @param dt data type
        @return ArrayStringable object or None.
        """
        if isinstance(dt, TypeDef):
            dt = (dt).get_base_data_type()
        return dt if isinstance(dt, ArrayStringable) else None

class Settings:
    pass

class MemBuffer:
    def is_initialized_memory(self) -> bool:
        pass
