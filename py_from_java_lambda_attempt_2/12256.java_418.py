Here's a translation of your Java interface into equivalent Python classes:

```Python
class Composite:
    def __init__(self):
        pass  # Initialize as needed for your specific use case.

    def set_description(self, desc: str) -> None:
        """Sets the string describing this data type."""
        raise NotImplementedError

    def get_num_components(self) -> int:
        """Gets the number of component data types in this composite."""
        raise NotImplementedError

    def get_num_defined_components(self) -> int:
        """Returns the number of explicitly defined components in this composite."""
        raise NotImplementedError

    def get_component(self, ordinal: int) -> 'DataTypeComponent':
        """Returns the component of this data type with the indicated ordinal."""
        raise IndexError("Ordinal out of bounds")

    def get_components(self) -> list['DataTypeComponent']:
        """Returns an array of Data Type Components that make up this composite including undefined filler components which may be present within a Structure where packing is disabled."""
        raise NotImplementedError

    def get_defined_components(self) -> list['DataTypeComponent']:
        """Returns an array of explicitly defined components in this composite excluding undefined filler components which may be present within Structures where packing is disabled."""
        raise NotImplementedError

    def add(self, data_type: 'DataType') -> 'DataTypeComponent':
        """Adds a new datatype to the end of this composite. This is the preferred method to use for adding components to an aligned structure for fixed-length dataTypes such as strings whose length must be specified."""
        raise ValueError("Invalid data type")

    def add(self, data_type: 'DataType', length: int) -> 'DataTypeComponent':
        """Adds a new datatype to the end of this composite. This is the preferred method to use for adding components to an aligned structure for dynamic dataTypes such as strings whose length must be specified."""
        raise ValueError("Invalid data type")

    def add(self, data_type: 'DataType', name: str, comment: str) -> 'DataTypeComponent':
        """Adds a new datatype to the end of this composite. This is the preferred method to use for adding components to an aligned structure for dynamic dataTypes such as strings whose length must be specified."""
        raise ValueError("Invalid data type")

    def insert(self, ordinal: int, data_type: 'DataType') -> 'DataTypeComponent':
        """Inserts a new datatype at the specified ordinal position in this composite. Note: For an aligned structure the ordinal position will get adjusted automatically to provide the proper alignment."""
        raise IndexError("Ordinal out of bounds")

    def delete(self, ordinals: set[int]) -> None:
        """Deletes the specified set of components at the given ordinal positions."""
        pass  # Implement as needed for your specific use case.

    def is_part_of(self, data_type: 'DataType') -> bool:
        """Check if a data type is part of this data type. A data type could be part of another by being the same data type or containing the data type directly or containing another data type that has the data type as a part of it."""
        raise NotImplementedError

    def data_type_alignment_changed(self, dt: 'DataType') -> None:
        """The alignment changed for the specified data type. If packing is enabled for this composite, the placement of the component may be affected by a change in its alignment. A non-packed composite can ignore this notification."""
        pass  # Implement as needed for your specific use case.

    def repack(self) -> None:
        """Updates packed composite to any changes in the data organization. If the composite does not have packing enabled, this method does nothing."""
        raise NotImplementedError

    def get_packing_type(self) -> 'PackingType':
        """Gets the current packing type (typically a power of 2)."""
        raise ValueError("Invalid packing type")

    @property
    def is_packing_enabled(self) -> bool:
        """Determine if this data type has its internal components currently packed based upon alignment and packing settings. If disabled, component placement is based upon explicit placement by offset."""
        return self.get_packing_type() != PackingType.DISABLED

    def set_packing_enabled(self, enabled: bool) -> None:
        """Sets whether this data type's internal components are currently packed. The affect of disabled packing differs between Structure and Union. When packing is disabled: Structures utilize explicit component offsets and produce undefined filler components where defined components do not consume space."""
        pass  # Implement as needed for your specific use case.

    def set_to_default_packing(self) -> None:
        """Enables default packing behavior. If packing was previously disabled, packing will be enabled. Composite will automatically pack based upon the alignment requirements of its components with overall composite length possibly influenced by the composite's minimum alignment setting."""
        pass  # Implement as needed for your specific use case.

    def get_alignment(self) -> int:
        """Get the computed alignment for this composite based upon packing and minimum alignment settings as well as component alignment. If packing is disabled, the alignment will always be 1 unless a minimum alignment has been set."""
        raise ValueError("Invalid alignment")

    @property
    def is_default_aligned(self) -> bool:
        """Whether or not this data type is using its default alignment. When Structure packing is disabled the default alignment is always 1 (see Structure.setPackingEnabled(boolean))."""
        return self.get_alignment_type() == AlignmentType.DEFAULT

    @property
    def is_machine_aligned(self) -> bool:
        """Whether or not this data type is using the machine alignment value, specified by DataOrganization.getMachineAlignment(), for its alignment."""
        raise ValueError("Invalid alignment")

    @property
    def has_explicit_minimum_alignment(self) -> bool:
        """Determine if an explicit minimum alignment has been set (see getExplicitMinimumAlignment()). An undefined value is returned if default alignment or machine alignment is enabled."""
        return self.get_alignment_type() == AlignmentType.EXPLICIT

    def get_explicit_minimum_alignment(self) -> int:
        """Get the explicit minimum alignment setting for this Composite which contributes to the actual computed alignment value (see getAlignment())."""
        raise ValueError("Invalid alignment")

    @property
    def has_packing_value_set(self) -> bool:
        """Determine if a packing value is set."""
        return self.get_packing_type() != PackingType.DISABLED

class DataTypeComponent:
    pass  # Implement as needed for your specific use case.

class PackingType:
    DISABLED = object()
    DEFAULT = object()
    EXPLICIT = object()

class AlignmentType:
    DEFAULT = object()
    MACHINE = object()
```

This Python code is a direct translation of the Java interface.