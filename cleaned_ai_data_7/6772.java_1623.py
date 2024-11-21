import ghidra_app_scripting as gappscript

class ApplyClassFunctionDefinitionUpdatesScript(gappscript.GhidraScript):
    def run(self):
        if self.current_program is None:
            print("There is no open program")
            return
        
        class_utils = RecoveredClassUtils(self.current_program, self.current_location,
                                          state.get_tool(), self, False, False, False)
        
        namespace = class_utils.get_class_namespace()
        if namespace is None:
            print("Either cannot retrieve class namespace or cursor is not in a member of a class namepace")
            return
        
        vftable_symbols = class_utils.get_class_vftable_symbols(namespace)
        if len(vftable_symbols) == 0:
            print("There are no vftables in this class")
            return
        
        print(f"Applying differing function definitions for class {namespace.name(true)}")

        changed_items = class_utils.apply_new_function_definitions(namespace, vftable_symbols)

        if not changed_items:
            print(f"No differences found for class {namespace.name(true)} between the vftable listing function signatures and their associated data type manager function definition data types")
            return
        
        structures_on_list = [s for s in changed_items if isinstance(s, gappscript.Structure)]
        function_definitions_on_list = [fd for fd in changed_items if isinstance(fd, gappscript.FunctionDefinition)]
        functions_on_list = [f for f in changed_items if isinstance(f, gappscript.Function)]

        print()
        print("Updated structures:")
        for structure in structures_on_list:
            self.monitor.check_canceled()
            print(structure.get_path_name())

        print()
        print("Updated function definitions:")
        for function_def in function_definitions_on_list:
            self.monitor.check_canceled()
            print(function_def.get_path_name())

        print()
        print("Updated functions:")
        for func in functions_on_list:
            self.monitor.check_canceled()
            print(func.entry_point().to_string())
