Here is the translation of the given Java code into equivalent Python:

```Python
from typing import Collection, List

class ProgramColumnConstraintProvider:
    def get_column_constraints(self) -> Collection[object]:
        constraints = []
        
        # @formatter:off
        
        constraints.append(AddressColumnConstraint(AtMostConstraint(UnsignedLongEditor.MAX_VALUE)))
        constraints.append(AddressColumnConstraint(AtLeastConstraint(BigInteger.ZERO)))
        constraints.append(AddressColumnConstraint(InRangeConstraint(BigInteger.ZERO, UnsignedLongEditor.MAX_VALUE, UnsignedLongRangeEditor())))
        constraints.append(AddressColumnConstraint(NotInRangeConstraint(BigInteger.ZERO, UnsignedLongEditor.MAX_VALUE, UnsignedLongRangeEditor())))

        # @formatter:on

        return [constraint for constraint in constraints]

class AddressToBigIntegerMapper:
    def convert(self, value: int) -> 'int':
        return NumericUtilities.unsigned_long_to_big_integer(value)

class MappedColumnConstraint(address_mapper):
    def __init__(self, delegate: object):
        super().__init__(AddressToBigIntegerMapper(), delegate)

    def copy(self, value: object) -> object:
        return self.__class__(value)


class AddressColumnConstraint(delegate):
    def __init__(self, constraint: object):
        super().__init__(new AddressToBigIntegerMapper(), constraint)
```

Please note that Python does not support direct translation of Java code into equivalent Python. The above code is a manual translation and may require some adjustments to work correctly in your specific use case.

Also, the `docking.widgets.table.constraint.*`, `ghidra.program.model.address.Address`, `NumericUtilities` are not available in standard Python libraries. You would need to implement these classes or import them from other modules if they exist.