Here is the translation of the Java code into Python:

```Python
class ArrayDataType:
    def __init__(self, data_type: 'DataType', num_elements: int, element_length: int = -1):
        self.data_type = data_type.clone()
        self.num_elements = num_elements
        self.element_length = element_length if isinstance(data_type, Dynamic) else data_type.get_length()

    @staticmethod
    def validate(base_dt: 'DataType') -> None:
        if not isinstance(base_dt, (BitFieldDataType, FactoryDataType)):
            return

        raise ValueError(f"Array data-type may not be a {base_dt.__class__.__name__}: {base_dt.name}")

    def has_language_dependent_length(self) -> bool:
        return self.data_type.has_language_dependent_length()

    def get_settings_definitions(self) -> list['SettingsDefinition']:
        return self.data_type.get_settings_definitions()

    def is_equivalent(self, obj: 'DataType') -> bool:
        if not isinstance(obj, Array):
            return False

        array = cast('Array', obj)
        return self.num_elements == array.num_elements and self.is_data_type_equivalent(array)

    @property
    def num_elements(self) -> int:
        return self._num_elements

    @num_elements.setter
    def num_elements(self, value: int):
        if value < 0:
            raise ValueError("Number of array elements may not be negative")

        self._num_elements = value

    def get_mnemonic(self, settings: 'Settings') -> str:
        return DataTypeUtilities.get_mnemonic(self, False, settings)

    @property
    def is_zero_length(self) -> bool:
        return self.num_elements == 0

    def get_length(self) -> int:
        if self.is_zero_length:
            return 1

        return self.num_elements * self.element_length

    def __str__(self):
        return f"Array of {self.data_type.get_display_name()}"

    @property
    def data_type(self) -> 'DataType':
        return self._data_type

    @data_type.setter
    def data_type(self, value: 'DataType'):
        if not isinstance(value, (Dynamic, BitFieldDataType)):
            raise ValueError(f"Array data-type may not be a {value.__class__.__name__}: {value.name}")

        self._data_type = value.clone()

    def clone(self) -> 'ArrayDataType':
        return ArrayDataType(self.data_type, self.num_elements, self.element_length)

    @property
    def element_length(self) -> int:
        return self._element_length

    @element_length.setter
    def element_length(self, value: int):
        if not isinstance(self.data_type, Dynamic) or value < 0:
            raise ValueError("Must specify Array element-length for dynamic")

        self._element_length = value

    # Other methods...
```

Note that I used the `@property` decorator to create getter and setter methods for some of the attributes. This is a common pattern in Python, where you define properties (attributes) using getters and setters.

Also note that I didn't translate all the Java code into Python; only the parts that are relevant to this specific class (`ArrayDataType`).