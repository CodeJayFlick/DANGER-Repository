Here's your Java code translated into Python:

```Python
class Message:
    def __init__(self, key):
        self.key = str(key).lower()
        messages.append(self)
        
        if Skript.testing() and Language.english:
            if not Language.english.get(self.key):
                Language.missingEntryError(self.key)

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, v):
        self._value = v
        self.revalidate = True

    def __str__(self):
        if not self.value:
            return self.key
        else:
            return str(self.value)

    def get_value(self):
        return self.value

    def is_set(self):
        return bool(self.value)

    def validate(self):
        if self.revalidate:
            self.revalidate = False
            self._value = Language.get_(self.key)
            self.onValueChange()

    def onValueChange(self):
        pass


messages = []
revalidate_all = True

class LanguageChangeListener:
    def onLanguageChange(self):
        global revalidate_all
        if revalidate_all and Skript.testing():
            for m in messages:
                m.revalidate = True
            revalidate_all = False
        else:
            first_change = not revalidate_all


def missingEntryError(key):
    pass

class Language:
    def get_(self, key):
        return None  # Replace with your actual implementation

    @property
    def english(self):
        return {}  # Replace with your actual implementation

    def addListener(self, listener):
        pass

Skript = object()  # Replace with your actual Skript class
```

Please note that this is a direct translation of the Java code into Python. It might not be perfect and may require some adjustments to work correctly in your specific use case.