Here is the translation of the Java code into Python:

```Python
import math

class VirtualFunctionTablePointerTypeApplier:
    def __init__(self, applicator, ms_type):
        if not isinstance(ms_type, (AbstractVirtualFunctionTablePointerMsType,
                                     AbstractVirtualFunctionTablePointerWithOffsetMsType)):
            raise ValueError("Invalid arguments")
        super().__init__(applicator, ms_type)

    @property
    def size(self):
        return math.BigInteger(str(applicator.data_organization.pointer_size))

    def get_offset(self):
        if isinstance(ms_type, AbstractVirtualFunctionTablePointerWithOffsetMsType):
            return (ms_type).get_offset()
        else:
            return 0

    def get_member_name(self):
        return f"VFTablePtr{self.get_offset()}"

    @property
    def data_type(self):
        pass

    def apply(self) -> None:
        if isinstance(ms_type, AbstractVirtualFunctionTablePointerMsType):
            self.data_type = self.apply_pointer((ms_type).get_pointer_type_record_number())
        else:
            self.data_type = self.apply_pointer((ms_type).get_pointer_type_record_number())

    @property
    def ms_type(self) -> 'AbstractMsType':
        return ms_type

    def apply_pointer(self, pointer_type_record_number):
        raw_applier = applicator.get_type_applier(pointer_type_record_number)
        if isinstance(raw_applier, PointerTypeApplier):
            return raw_applier.data_type
        else:
            applicator.append_log_msg(f"cannot process {raw_applier.__class__.__name__} for {self.__class__.__name__}")
            return None

    @staticmethod
    def validate_type(type: 'AbstractMsType') -> 'AbstractMsType':
        if not isinstance(type, (AbstractVirtualFunctionTablePointerMsType,
                                 AbstractVirtualFunctionTablePointerWithOffsetMsType)):
            raise ValueError(f"PDB Incorrectly applying {type.__class__.__name__} to {VirtualFunctionTablePointerTypeApplier.__name__}")
        return type

    @property
    def applicator(self):
        pass

    @applicator.setter
    def applicator(self, value):
        self._applicator = value


# Example usage:
ms_type = AbstractMsType()  # Replace with actual ms_type instance
applier = VirtualFunctionTablePointerTypeApplier(applicator=Applicator(), ms_type=ms_type)
print(applier.get_member_name())
```

Please note that Python does not have direct equivalent of Java's `BigInteger` class. You can use the built-in integer type or a library like `gmpy2`. Also, this code assumes you have classes `AbstractMsType`, `Applicator`, and their subclasses defined elsewhere in your program.