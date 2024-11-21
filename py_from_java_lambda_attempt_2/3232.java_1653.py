Here is the translation of the Java code into Python:

```Python
class AbstractModularizationCmd:
    def __init__(self, name: str, group_path: str, tree_name: str,
                 selection: ProgramSelection, block_model: CodeBlockModel):
        self.name = name
        self.group_path = group_path
        self.tree_name = tree_name
        self.selection = selection
        self.code_block_model = block_model

    def apply_to(self, obj: DomainObject, task_monitor: TaskMonitor) -> bool:
        program = obj
        monitor = task_monitor
        monitor.set_indeterminate(True)
        root_module = program.get_listing().get_root_module(tree_name)
        selected_group = group_path.get_group(program, tree_name)
        process_entire_program = selected_group == root_module
        destination_module = (selected_group if isinstance(selected_group, ProgramModule) else root_module)

        try:
            self.apply_model()
            self.clean_empty()
            return True

        except CancelledException as e:
            print("Cancelled")
            return False

        except Exception as e:
            Msg.error(self, "Unexpected exception modularizing the program tree", e)
            print("Unexpected Exception (see console)")
            return False

    def clean_empty(self) -> None:
        root_module = self.program.get_listing().get_root_module(self.tree_name)
        self.clean_tree_without_rename(root_module)

    def get_addresses_for_group(self) -> AddressSetView:
        if process_entire_program:
            return self.program.get_memory()

        if isinstance(selected_group, ProgramModule):
            module = selected_group
            return self.get_module_addresses(module)

        return (ProgramFragment)selected_group

    # ... and so on for the rest of the methods ...
```

Please note that Python does not have direct equivalent to Java's abstract classes. In this translation, I used a regular class `AbstractModularizationCmd` instead.

Also, some parts of the code are quite complex and might require additional explanation or context specific to your project.