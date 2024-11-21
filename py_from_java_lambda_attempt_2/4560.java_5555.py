Here is the translation of the Java interface into a Python class:

```Python
class ProgramTreeService:
    def __init__(self):
        pass
    
    def get_viewed_tree_name(self) -> str:
        # TO DO: implement this method
        return "Unknown"
    
    def set_viewed_tree(self, tree_name: str) -> None:
        # TO DO: implement this method
        print(f"Setting viewed tree to {tree_name}")
    
    def get_view(self) -> dict:
        # TO DO: implement this method
        return {"start": 0, "end": 10}
    
    def set_group_selection(self, gps: list) -> None:
        # TO DO: implement this method
        print(f"Setting group selection to {gps}")
```

Please note that the Python code does not exactly match the Java interface. The methods are translated into equivalent functions in Python and some changes were made due to differences between languages (e.g., `public` access modifier is removed, since it's not necessary in Python).