Here is the translation of the given Java code into Python:

```Python
class HandleTemplate:
    def __init__(self, space: 'ConstantTemplate', ptr: 'VarnodeTemplate', size: 'ConstantTemplate'):
        self.space = space
        self.ptr = ptr
        self.size = size


    def resolve(self, handles: dict, position: int, off: int) -> 'Handle':
        v = self.ptr.resolve(handles, position, off)
        sp = int(self.space.resolve(handles, position, off))
        sz = int(self.size.resolve(handles, position, off))
        return Handle(v, sp, sz)


    def resolve(self, position: int, off: int) -> 'Handle':
        v = self.ptr.resolve(position, off)
        sp = int(self.space.resolve(position, off))
        sz = int(self.size.resolve(position, off))
        return Handle(v, sp, sz)

class ConstantTemplate:
    pass

class VarnodeTemplate:
    def resolve(self, handles: dict, position: int, off: int) -> 'Varnode':
        # implement the logic here
        pass


    def resolve(self, position: int, off: int) -> 'Varnode':
        # implement the logic here
        pass

class Handle:
    def __init__(self, v: 'Varnode', sp: int, sz: int):
        self.v = v
        self.sp = sp
        self.sz = sz


# Example usage:

space_template = ConstantTemplate()
ptr_template = VarnodeTemplate()

handle_template = HandleTemplate(space_template, ptr_template, space_template)

print(handle_template.resolve({}, 0, 0))
```

Please note that the `Varnode`, `ConstantTemplate` and their respective templates are not implemented in this translation. You would need to implement these classes based on your specific requirements.