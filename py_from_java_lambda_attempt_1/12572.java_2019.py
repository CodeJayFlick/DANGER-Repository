Here is the translation of the Java interface into a Python class:

```Python
class ProgramTreeChangeSet:
    def __init__(self):
        self.changed_trees = []
        self.added_trees = []

    # Program Tree
    
    def program_tree_changed(self, id: int) -> None:
        """adds the program tree id to the list of trees that have changed."""
        self.changed_trees.append(id)

    def program_tree_added(self, id: int) -> None:
        """adds the program tree id to the list of trees that have been added."""
        self.added_trees.append(id)
    
    def get_program_tree_changes(self) -> list[int]:
        """returns the list of program tree IDs that have changed."""
        return self.changed_trees
    
    def get_program_tree_additions(self) -> list[int]:
        """returns the list of program tree IDs that have been added."""
        return self.added_trees
```

Note: In Python, we don't need to declare types for variables or function parameters. The `__init__` method is used to initialize class attributes when an object is created.