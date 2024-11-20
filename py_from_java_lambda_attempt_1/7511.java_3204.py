Here is the translation of the Java code to Python:
```
class FGVertexListingModel:
    def __init__(self, program, format_manager):
        super().__init__(program, format_manager)
        self.is_dirty = False

    def refresh(self):
        if not self.is_dirty:
            return False
        self.is_dirty = False
        if not self.program.is_closed():
            self.notify_data_changed(True)
            return True
        return False

    def domain_object_changed(self, ev):
        self.is_dirty = True

# Note: In Python, we don't have a direct equivalent of Java's "package" statement.
# Instead, you would typically put this class in its own file (e.g. `fg_vertex_listing_model.py`)
```
Note that I've used the following equivalences:

* `class` is the same as in Java
* `extends` becomes `super().__init__()` to call the parent constructor
* `private` variables become instance attributes with no explicit access modifier
* `@Override` annotation is not needed, since Python doesn't have method overriding syntax like Java does
* Method calls are similar between Java and Python, but note that in Python we use parentheses instead of square brackets for function calls.
* The rest of the code remains largely unchanged.