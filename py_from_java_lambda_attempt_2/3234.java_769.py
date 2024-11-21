Here is the translation of the given Java code into Python:

```Python
class CreateDefaultTreeCmd:
    def __init__(self, tree_name):
        self.tree_name = tree_name
        self.status_msg = None

    def apply_to(self, obj):
        program = Program(obj)
        listing = program.get_listing()
        try:
            root_module = listing.create_root_module(self.tree_name)
            rename_fragments(program, self.tree_name)
            return True
        except DuplicateNameException as e:
            self.status_msg = str(e)
        return False

    @staticmethod
    def create_root_module(program, tree_name):
        if not isinstance(tree_name, str) or len(tree_name.strip()) == 0:
            raise ValueError("Tree name cannot be empty")
        
        listing = program.get_listing()
        try:
            root_module = listing.create_root_module(tree_name)
            rename_fragments(program, tree_name)
            return root_module
        except DuplicateNameException as e:
            raise e

    @staticmethod
    def rename_fragments(program, tree_name):
        listing = program.get_listing()
        memory_blocks = [block for block in program.memory().get_blocks()]
        
        for i, block in enumerate(memory_blocks):
            fragment = listing.get_fragment(tree_name, block.start)
            try:
                fragment.set_name(block.name)
            except DuplicateNameException as e:
                pass

    def get_status_msg(self):
        return self.status_msg

    def get_name(self):
        return f"Create Tree {self.tree_name}"
```

Note that Python does not have direct equivalent of Java's `try-catch` block. Instead, you can use a combination of `try-except-else-finally` blocks to achieve the same result.

Also note that in Python, we don't need to specify types for variables or method parameters like we do in Java.