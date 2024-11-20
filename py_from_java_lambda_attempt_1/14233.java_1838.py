Here is the translation of the Java code to Python:

```Python
class PropertiesFeatureToggleVersion:
    def __init__(self, properties):
        if not properties:
            raise ValueError("No Properties Provided.")
        try:
            self.enhanced = bool(properties.get("enhancedWelcome"))
        except Exception as e:
            raise ValueError("Invalid Enhancement Settings Provided.")

    @property
    def enhanced(self):
        return self._enhanced

    def get_welcome_message(self, user):
        if self.enhanced:
            return f"Welcome {user}. You're using the enhanced welcome message."
        else:
            return "Welcome to the application."

if __name__ == "__main__":
    properties = {"enhancedWelcome": True}
    ftv = PropertiesFeatureToggleVersion(properties)
    user = "John"
    print(ftv.get_welcome_message(user))
```

Note that Python does not have a direct equivalent of Java's `@Getter` annotation, so I used the `@property` decorator to create a read-only property for the `enhanced` attribute.