Here is the translation of the Java code to Python:
```python
import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import *
from ghidra.program.model.symbol import *

class RemoveDeletedOverlayReferences(GhidraScript):
    def run(self) -> None:
        ref_mgr = self.current_program.get_reference_manager()
        it = ref_mgr.get_reference_destination_iterator(self.current_program.get_min_address(), True)
        total_refs = 0
        total_deleted_refs = 0
        bad_refs = []
        while it.has_next():
            address = it.next()
            ref_iter = ref_mgr.get_references_to(address)
            while ref_iter.has_next():
                ref = ref_iter.next()
                total_refs += 1
                if ref.get_from_address().get_address_space().type == AddressSpace.TYPE_DELETED:
                    total_deleted_refs += 1
                    bad_refs.append(ref)
        for reference in bad_refs:
            ref_mgr.delete(reference)
        print(f"total refs = {total_refs}, deleted refs = {total_deleted_refs}")
```
Note that I've used the `GhidraScript` class from the Ghidra API, and imported the necessary modules (`AddressSpace`, etc.) to access the relevant classes. The rest of the code is a straightforward translation of the Java code to Python.