Here is the translation of the Java code into Python:

```Python
from typing import Any

class BaseClassTypeApplier:
    def __init__(self, applicator: Any, ms_type: Any) -> None:
        if not isinstance(ms_type, (AbstractBaseClassMsType, AbstractVirtualBaseClassMsType, 
                                    AbstractIndirectVirtualBaseClassMsType)):
            raise ValueError("Invalid MsType")
        super().__init__(applicator, ms_type)

    def get_size(self) -> int:
        return 0

    def get_offset(self) -> int:
        if isinstance(ms_type, AbstractBaseClassMsType):
            return (ms_type).get_offset()
        else:
            raise PdbException("Offset is not a valid field")

    def get_base_pointer_offset(self) -> int:
        if isinstance(ms_type, AbstractBaseClassMsType):
            raise PdbException("Base Pointer Offset is not valid field")
        elif isinstance(ms_type, (AbstractVirtualBaseClassMsType, 
                                 AbstractIndirectVirtualBaseClassMsType)):
            return (ms_type).get_base_pointer_offset()
        else:
            pass

    def get_attributes(self) -> Any:
        if isinstance(ms_type, AbstractBaseClassMsType):
            return ms_type.get_attributes()
        elif isinstance(ms_type, (AbstractVirtualBaseClassMsType, 
                                 AbstractIndirectVirtualBaseClassMsType)):
            return ms_type.get_attributes()

    def get_base_class_record_number(self) -> int:
        if isinstance(ms_type, AbstractBaseClassMsType):
            return ms_type.get_base_class_record_number()
        elif isinstance(ms_type, (AbstractVirtualBaseClassMsType, 
                                 AbstractIndirectVirtualBaseClassMsType)):
            return ms_type.get_base_class_record_number()

    def has_virtual_base_pointer_type_index(self) -> bool:
        return not isinstance(ms_type, AbstractBaseClassMsType)

    def get_virtual_base_pointer_record_number(self) -> int:
        if isinstance(ms_type, (AbstractVirtualBaseClassMsType, 
                               AbstractIndirectVirtualBaseClassMsType)):
            return ms_type.get_virtual_base_pointer_record_number()
        else:
            raise PdbException("Not a virtual base class")

    def apply(self) -> None:
        pass

class MsTypeApplier:
    def __init__(self, applicator: Any, ms_type: Any) -> None:
        super().__init__(applicator, ms_type)

# You will need to define these classes yourself
AbstractBaseClassMsType = ...
AbstractVirtualBaseClassMsType = ...
AbstractIndirectVirtualBaseClassMsType = ...

PdbException = ...  # This should be a custom exception class

CancelledException = ...  # This should be a custom exception class
```

Please note that you will need to define the `AbstractBaseClassMsType`, `AbstractVirtualBaseClassMsType`, and `AbstractIndirectVirtualBaseClassMsType` classes yourself, as well as the `PdbException` and `CancelledException`.