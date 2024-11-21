Here is the equivalent Python code:

```Python
class HasCustomModelData:
    def __init__(self):
        self.name = "Has Custom Model Data"
        self.description = "Check if an item has a custom model data tag"
        self.examples = ["player's tool has custom model data"]
        self.required_plugins = ["1.14+"]
        self.since = "2.5"

    def check(self, item):
        return item.get_item_meta().has_custom_model_data()

    @property
    def property_name(self):
        return "custom model data"
```

Note that Python does not have direct equivalents to Java's package system or annotations like `@Name`, `@Description`, etc. So I've simply assigned these values as attributes of the class in this translation.