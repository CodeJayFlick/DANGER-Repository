Here's a translation of the Java interface into equivalent Python:

```Python
class LocationReferencesService:
    MENU_GROUP = "References"

    def get_help_location(self):
        # Implement this method in your subclass.
        pass

    def show_references_to_location(self, location: 'ProgramLocation', navigatable: 'Navigatable'):
        if not isinstance(location, ProgramLocation) or not isinstance(navigatable, Navigatable):
            raise TypeError("Invalid type")
        
        # Your implementation here
```

Please note that Python does not have direct equivalent of Java's interface. It has classes and abstract base classes (ABCs). The above code is a class definition in Python which serves the same purpose as an interface in Java.

Also, note that I've used `pass` for methods where you would typically return something or throw an exception. You should replace these with your actual implementation.