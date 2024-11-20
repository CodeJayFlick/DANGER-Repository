Here is the equivalent Python code:

```Python
class RemoveExternalRefCmd:
    def __init__(self, from_addr, op_index):
        self.from_addr = from_addr
        self.op_index = op_index

    def apply_to(self, obj):
        ref_mgr = (obj).get_reference_manager()
        refs = ref_mgr.get_references_from(from_addr, op_index)
        for i in range(len(refs)):
            ref = refs[i]
            if ref.is_external_reference():
                ref_mgr.delete(ref)

        return True

    def get_status_msg(self):
        return None

    def get_name(self):
        return "Remove External Reference"
```

Note that Python does not have direct equivalents to Java's `public`, `private`, and other access modifiers. In Python, all class members are public by default. Also, the equivalent of Java's constructor is a special method named `__init__` in Python.