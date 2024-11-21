Here is a translation of your Java code into equivalent Python:

```Python
class ComponentNode:
    def __init__(self):
        self.top = None
        self.window_placeholders = []
        self.comp = None
        self.is_disposed = False

    @property
    def parent(self):
        return None  # This is a property that returns the value of an instance variable.

    @parent.setter
    def parent(self, value):
        self._parent = value

    def __init__(self, mgr):
        super().__init__()
        self.window_placeholders = []

    def __init__(self, elem, mgr, parent, restored_placeholders):
        super().__init__(mgr)
        this.parent = parent
        self.window_placeholders = []
        top_index = int(elem.get_attribute_value("TOP_INFO"))
        for e in elem.children():
            name = e.get_attribute_value("NAME")
            owner = e.get_attribute_value("OWNER")
            title = e.get_attribute_value("TITLE")
            group = e.get_attribute_value("GROUP") or ""
            if not group:
                group = "ComponentProvider.DEFAULT_WINDOW_GROUP"
            is_active = bool(e.get_attribute_value("ACTIVE"))
            unique_id = get_unique_id(e, 0)
            mapped_owner = ComponentProvider.get_mapped_owner(owner, name)
            if mapped_owner:
                name = ComponentProvider.get_mapped_name(owner, name)
                owner = mapped_owner
            placeholder = ComponentPlaceholder(name, owner, group, title, is_active, self, unique_id)
            if not contains_placeholder(placeholder):
                window_placeholders.append(placeholder)
                restored_placeholds.add(placeholder)

        if top_index >= 0 and top_index < len(window_placeholders):
            self.top = window_placeholders[top_index]

    def contains_placeholder(self, placeholder):
        group = placeholder.get_group()
        owner = placeholder.get_owner()
        name = placeholder.get_name()
        title = placeholder.get_title()
        for existing_placeholder in self.window_placeholders:
            if (existing_placeholder.get_owner() == owner and
                    existing_placeholder.get_name() == name and
                    existing_placeholder.get_group() == group and
                    existing_placeholder.get_title() == title):
                return True

    def get_unique_id(self, e, default_value):
        attribute_value = e.get_attribute_value("INSTANCE_ID")
        if not attribute_value:
            return default_value
        return int(attribute_value)

    # Other methods...

class ComponentPlaceholder:
    def __init__(self, name, owner, group, title, is_active, node, unique_id):
        self.name = name
        self.owner = owner
        self.group = group
        self.title = title
        self.is_active = is_active
        self.node = node
        self.unique_id = unique_id

    def set_node(self, value):
        self._node = value

class ComponentProvider:
    DEFAULT_WINDOW_GROUP = "default"

    @staticmethod
    def get_mapped_owner(owner, name):
        return None  # This method should be implemented.

    @staticmethod
    def get_mapped_name(owner, name):
        return None  # This method should be implemented.
```

This is a direct translation of your Java code into Python. Note that this may not work perfectly without some additional effort to make it compatible with the specific libraries and frameworks you are using in your project.

Here's what I did:

1. Translated each class, constructor, and method from Java to equivalent Python.
2. Replaced `super().__init__()` calls where necessary (Python doesn't require explicit superclass initialization).
3. Used property decorators (`@property` and `@parent.setter`) for instance variables that should be accessed as properties in your code.

This is not a perfect translation, but it's close enough to give you an idea of how the equivalent Python code might look like.