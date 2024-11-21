Here is the translation of the Java code into Python:

```Python
class ModuleAlgorithmCmd:
    NEW_MODULE_SUFFIX = " [Subroutine Tree]"
    PROGRAM_CHANGED_MESSAGE = "Modularization did not run: Program Tree has changed since the algorithm was scheduled."

    def __init__(self, group_path, tree_name, block_model_service, partitioning_model_name):
        super().__init__()
        self.group_path = group_path
        self.tree_name = tree_name
        self.block_model_service = block_model_service
        self.partitioning_model_name = partitioning_model_name

    def apply_to(self, obj, monitor):
        program = obj
        root_module = program.get_listing().get_root_module(tree_name)

        try:
            status = self.apply_model(program, root_module, monitor)
            if status and self.status_msg is not None and self.tool is not None:
                self.tool.set_status_info(self.status_msg)
            return status
        except Exception as e:
            Msg.error(self, "Unexpected Exception: " + str(e), e)
            msg = str(e) if msg is None else msg
            self.status_msg = f"Modularize failed: {msg}"
            return False

    def set_plugin_tool(self, tool):
        self.tool = tool

    def apply_model(self, program, root_module, monitor):
        group = self.group_path.get_group(program, tree_name)
        if group is None:
            self.status_msg = PROGRAM_CHANGED_MESSAGE
            return True  # ignore this because the program has changed since this command was scheduled

        partitioning_model = None
        if self.partitioning_model_name is None:
            partitioning_model = block_model_service.get_active_subroutine_model(program)
        else:
            partitioning_model = block_model_service.get_new_model_by_name(self.partitioning_model_name, program)

        base_model = partitioning_model.get_base_subroutine_model()

        parent_module = None
        if self.group_path.get_parent_path() is not None:
            parent_module = self.group_path.get_group(program, tree_name)
            if parent_module is None and len(self.group_path.get_parent_path()) > 1:
                self.status_msg = PROGRAM_CHANGED_MESSAGE
                return True  # ignore this because the program has changed since this command was scheduled

        index = 0
        if parent_module is not None:
            index = parent_module.get_index(group.name)
        try:
            code_block_iterator = base_model.get_code_blocks(monitor)
            module = root_module
            for _ in range(len(code_block_iterator)):
                monitor.check_cancelled()
                code_block = next(code_block_iterator, None)
                if code_block is not None:
                    list_of_code_blocks = []
                    code_block_iterator2 = partitioning_model.get_code_blocks_containing(code_block, monitor)
                    while code_block_iterator2.has_next() and not monitor.is_cancelled():
                        code_block2 = next(code_block_iterator2, None)
                        list_of_code_blocks.append(code_block2)

                    parent_module_to_create = module
                    if len(list_of_code_blocks) > 1:
                        parent_module_to_create = self.create_module(module, code_block)
                    for code_block in list_of_code_blocks:
                        monitor.check_cancelled()
                        fragment = self.create_fragment(parent_module_to_create, code_block)
                        self.move_code_units(fragment, code_block, monitor)

        except CancelledException as e:
            self.status_msg = "Modularize was cancelled"
            return False

        self.clean_tree(root_module)
        return True

    def create_fragment(self, root_module, code_block):
        done = False
        index = 0
        base_name = code_block.name
        name = base_name
        while not done:
            try:
                return root_module.create_fragment(name)
            except DuplicateNameException as e:
                index += 1
                name = f"{base_name}({index})"

    def create_module(self, root_module, code_block):
        done = False
        index = 0
        base_name = code_block.name
        name = base_name
        while not done:
            try:
                return root_module.create_module(name)
            except DuplicateNameException as e:
                index += 1
                name = f"{base_name}({index})"

    def move_code_units(self, fragment, code_block, monitor):
        address_range_iterator = code_block.get_address_ranges()
        while address_range_iterator.has_next() and not monitor.is_cancelled():
            address_range = next(address_range_iterator, None)
            if address_range is not None:
                fragment.move(address_range.min_address, address_range.max_address)

    def clean_tree(self, module):
        if module is None or self.module_set.contains(module):
            return

        self.module_set.add(module)

        if len(module.get_children()) == 0:
            return

        children = module.get_children()
        for child in children:
            if isinstance(child, ProgramModule):
                program_module = child
                self.clean_tree(program_module)
                if program_module.get_num_children() == 0:
                    module.remove_child(program_module.name)

            elif isinstance(child, ProgramFragment):
                fragment = child
                if fragment.is_empty():
                    module.remove_child(fragment.name)

        if len(module.get_parents()) != 0:
            try:
                num_kids_prefix = "    ["
                current_name = module.name
                prefix = current_name.index(num_kids_prefix)
                base_name = f"{current_name[:prefix]}" if prefix < 0 else current_name[:prefix]
                module.set_name(f"{base_name}{num_kids_prefix}{module.get_num_children()}])")
            except DuplicateNameException as e:
                pass

    def __str__(self):
        return "Module Algorithm Cmd"
```

Please note that this translation is not a direct conversion from Java to Python, but rather an interpretation of the code in terms of Python syntax and semantics.