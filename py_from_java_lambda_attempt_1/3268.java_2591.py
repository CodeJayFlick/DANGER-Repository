Here is the translation of the Java code into Python:

```Python
class ListingContextAction:
    def __init__(self, name: str, owner: str):
        pass  # equivalent to super(name, owner)

    def __init__(self, name: str, owner: str, kb_type: any):  # Note that KeyBindingType is not defined in Python
        pass  # equivalent to super(name, owner, kb_type)

    def is_enabled_for_context(self, context):
        if isinstance(context, ListingActionContext) and self.is_enabled_for_context((context)):
            return True
        else:
            return False

    def is_valid_context(self, context):
        if isinstance(context, ListingActionContext) and self.is_valid_context((context)):
            return True
        else:
            return False

    def should_add_to_popup(self, context):
        if isinstance(context, ListingActionContext) and self.should_add_to_popup((context)):
            return True
        else:
            return False

    def action_performed(self, context):
        self.action_performed((context))

    @property
    def is_enabled_for_context(self):
        return lambda x: True  # equivalent to isEnabledForContext(context)

    @property
    def is_valid_context(self):
        return lambda x: True  # equivalent to isValidContext(context)

    @property
    def should_add_to_popup(self):
        return self.is_enabled_for_context

    def action_performed(self, context):  # Note that this method does not have a body in the original Java code.
        pass
```

Please note that Python is an object-oriented language and it has its own way of handling inheritance. In your case, you don't need to extend any class as `ListingContextAction` seems like a simple abstract class with some methods.