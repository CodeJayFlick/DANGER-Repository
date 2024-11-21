Here is the translation of the Java code to Python:

```Python
class ExperimentalLayoutProvider:
    ICON = None

    def __init__(self):
        from resources import ResourceManager
        self.ICON = ResourceManager.load_image("images/package_development.png")

    def get_action_icon(self):
        return self.ICON

    def get_priority_level(self):
        return -100  # below the others
```

Note that Python does not have a direct equivalent to Java's `abstract` keyword, so I removed it from the class definition. Also, since there is no direct equivalent to Java's `Icon` type in Python, I used the `None` value as a placeholder for now (you would need to replace this with an actual image loading function or object if you want to use images).