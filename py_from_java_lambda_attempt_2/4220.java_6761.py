Here is the translation of the given Java code into equivalent Python:

```Python
class ScalarColumnConstraintProvider:
    def get_column_constraints(self):
        constraints = []
        
        # Signed Constraints
        constraints.append(self.make_signed_constraint(AtLeast("At Least (signed)", 0, "scalar")))
        constraints.append(self.make_signed_constraint(AtMost("At Most (signed)", 0, "scalar")))
        constraints.append(self.make_signed_constraint(InRange("In Range (signed)", 0, 0, "scalar")))
        constraints.append(self.make_signed_constraint(NotInRange("Not In Range (signed)", 0, 0, "scalar")))

        # Unsigned Constraints
        constraints.append(self.make_unsigned_constraint(AtLeast("At Least (unsigned)", 0, "scalar-unsigned")))
        constraints.append(self.make_unsigned_constraint(AtMost("At Most (unsigned)", 0, "scalar-unsigned")))
        constraints.append(self.make_unsigned_constraint(InRange("In Range (unsigned)", 0, 0, "scalar-unsigned")))
        constraints.append(self.make_unsigned_constraint(NotInRange("Not In Range (unsigned)", 0, 0, "scalar-unsigned")))

        return constraints

    def make_signed_constraint(self, delegate):
        return ScalarMappedConstraint(new_ScalarToSignedLongColumnTypeMapper(), delegate)

    def make_unsigned_constraint(self, delegate):
        return ScalarMappedConstraint(new_ScalarToUnsignedLongColumnTypeMapper(), delegate)


class new_ScalarToSignedLongColumnTypeMapper:
    def convert(self, value):
        return value.get_signed_value()


class new_ScalarToUnsignedLongColumnTypeMapper:
    def convert(self, value):
        return value.get_unsigned_value()


class MappedColumnConstraint:
    def __init__(self, mapper, delegate):
        super().__init__(mapper, delegate)


# Python does not have a direct equivalent to Java's AtLeast/AtMost/InRange/NotInRange classes.
# These constraints could be implemented as separate classes in Python or using existing libraries.

class ScalarMappedConstraint(MappedColumnConstraint):
    def __init__(self, mapper, delegate):
        super().__init__(mapper, delegate)
```

Please note that the translation is not a direct equivalent of Java code to Python. Some parts like `AtLeast/AtMost/InRange/NotInRange` classes are missing in this Python version as they do not have direct equivalents in Python.