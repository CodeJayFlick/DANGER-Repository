Here is the translation of the Java code into Python:

```Python
class GenericDataFlavor:
    def __init__(self):
        pass

    @classmethod
    def from_representation_class(cls, representation_class, human_presentable_name=None):
        if human_presentable_name is None:
            return cls(f"application/x-java-serialized-object; class={representation_class.__name__}", f"{human_presentable_name}")
        else:
            return cls(f"application/x-java-serialized-object; class={representation_class.__name__}", human_presentable_name)

    @classmethod
    def from_mime_type(cls, mime_type):
        try:
            representation_class = eval("eval('import java.lang.ClassForName' ; Class.forName('" + mime_type.split(";")[1].split("=")[1] + "'))")
            return cls(mime_type, human_presentable_name=representation_class.__name__)
        except Exception as e:
            print(f"Error: {e}")
            return None

    def __eq__(self, other):
        if isinstance(other, GenericDataFlavor):
            return self.get_human_presentable_name() == other.get_human_presentable_name()
        elif isinstance(other, str):
            try:
                representation_class = eval("eval('import java.lang.ClassForName' ; Class.forName('" + other.split(";")[1].split("=")[1] + "'))")
                return self.get_human_presentable_name() == representation_class.__name__
            except Exception as e:
                print(f"Error: {e}")
                return False
        else:
            return super().__eq__(other)

    def get_human_presentable_name(self):
        # This method should be implemented in the subclass.
        pass

# Example usage:

class MyDataFlavor(GenericDataFlavor):
    def __init__(self, human_presentable_name="My Data Flavor"):
        self._human_presentable_name = human_presentable_name
        super().__init__()

    def get_human_presentable_name(self):
        return self._human_presentable_name

my_data_flavor = MyDataFlavor()
print(my_data_flavor.equals(MyDataFlavor()))  # True
print(my_data_flavor.equals("application/x-java-serialized-object; class=MyClass"))  # False
```

Please note that the `get_human_presentable_name` method should be implemented in any subclass of `GenericDataFlavor`.