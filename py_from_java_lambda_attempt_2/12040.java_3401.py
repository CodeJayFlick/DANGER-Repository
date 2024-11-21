Here is the translation of the given Java code into Python:

```Python
class ExternalReferenceDB:
    def __init__(self, program: 'Program', from_addr: int, to_addr: int, ref_type: str, op_index: int, source_type: str):
        self.program = program
        super().__init__(from_addr, to_addr, ref_type, op_index, source_type)

    def equals(self, obj) -> bool:
        if not isinstance(obj, ExternalReferenceDB):
            return False

        if (obj.from_addr == self.from_addr and 
           obj.op_index == self.op_index and
           obj.source_type == self.source_type and
           obj.ref_type == self.ref_type):

            external_location = self.get_external_location()
            if external_location is not None:
                return external_location.is_equivalent(obj.get_external_location())

        return False

    def __str__(self) -> str:
        return "->" + str(self.get_external_location())

    @property
    def is_external_reference(self) -> bool:
        return True

    def get_external_location(self):
        ext_mgr = self.program.external_manager()
        return ext_mgr.get_ext_location(self.to_addr)

    @property
    def library_name(self) -> str:
        return self.get_external_location().library_name()

    @property
    def label(self) -> str:
        return self.get_external_location().label()


class Program:
    pass


class ExternalReferenceDB(Program):
    pass


class Address:
    pass


class Reference:
    pass


class ExternalLocation:
    def is_equivalent(self, other: 'ExternalLocation') -> bool:
        pass

    @property
    def library_name(self) -> str:
        pass

    @property
    def label(self) -> str:
        pass
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. It is used to indicate that a method is overriding a method in the parent class, but it is not enforced by the language itself.

Also, I've assumed some classes (`Program`, `Address`, `Reference`, and `ExternalLocation`) which are not defined in your code snippet. You would need to define these classes or use existing ones if they exist in Python.