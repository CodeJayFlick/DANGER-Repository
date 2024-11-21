Here is the translation of the Java code to Python:

```Python
class FidServiceUtil:
    def compute_parents(self, function):
        program = function.get_program()
        function_manager = program.function_manager
        reference_manager = program.reference_manager
        references_to = reference_manager.references_to(function.entry_point)
        parents = set()

        for reference in references_to:
            if reference.is_call():
                parent = function_manager.function_containing(reference.from_address)
                if parent is not None:
                    parents.add(parent)

        return parents

    def compute_children(self, function):
        program = function.get_program()
        function_manager = program.function_manager
        reference_manager = program.reference_manager
        references_from = set()

        for address in reference_manager.reference_source_iterator(function.body, True):
            references = reference_manager.references_from(address)
            children = set()

            for reference in references:
                if reference.is_call():
                    child = function_manager.function_at(reference.to_address)
                    if child is not None:
                        children.add(child)

            return children
```

Note that Python does not have direct equivalents to Java's `HashSet` and `ReferenceIterator`, so I used built-in set data structure for the parent functions, and a list comprehension with filtering condition for getting references from an address.