Here is a translation of the Java code into equivalent Python:

```Python
class JdiModelTargetConstantPool:
    def __init__(self, parent, pool, is_element):
        self.parent = parent
        self.pool = pool
        self.range = None
        
        super().__init__(parent, "Constant Pool", pool, is_element)
        
    @property
    def range(self):
        return self._range
    
    @range.setter
    def range(self, value):
        if value:
            self._range = value

    def request_attributes(self, refresh=False):
        self.range = self.parent.impl.get_address_range(self.class_type(), len(self.pool))
        
        if self.range is not None:
            super().change_attributes([], [], {"Initialized": "Constant Pool"}, "Initialized")
            
        return CompletableFuture.completed_future(None)

    @property
    def class_type(self):
        return (self.parent).class_type

    def get_display(self):
        return f"{self.class_type.name}: ConstPool{self.range}"

    def init(self):
        return CompletableFuture.completed_future(None)
```

Note that this translation is not a direct conversion from Java to Python, but rather an equivalent implementation in Python.