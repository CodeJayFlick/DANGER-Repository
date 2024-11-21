Here is the translation of the Java interface into a Python class:

```Python
class ButtonPressedListener:
    def button_pressed(self, location: 'ProgramLocation', 
                      field_location: 'FieldLocation', field: 'ListingField', event):
        pass  # implement this method in your subclass
```

Note that I've used type hints for the parameters to make it clear what types of objects are expected. However, Python is a dynamically-typed language and does not enforce these types at runtime.

Also note that there's no direct equivalent of Java interfaces in Python; instead, you can use abstract base classes (ABCs) or just define an empty class with methods declared as `pass`.