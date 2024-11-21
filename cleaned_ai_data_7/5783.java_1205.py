class FunctionMerge:
    def __init__(self, origin_to_result_translator):
        self.origin_to_result_translator = origin_to_result_translator
        self.from_program = origin_to_result_translator.get_source_program()
        self.to_program = origin_to_result_translator.get_destination_program()
        self.from_function_manager = from_program.get_function_manager()
        self.to_function_manager = to_program.get_function_manager()

    @staticmethod
    def is_default_thunk(func):
        return func.get_symbol().get_source() == 'DEFAULT' and func.is_thunk()

    def replace_function_symbol(self, origin_entry_point, conflict_symbol_id_map, monitor=None):
        if monitor:
            monitor.set_message("Replacing function symbol...")
        
        result_entry_point = self.origin_to_result_translator.get_address(origin_entry_point)
        from_func = self.from_function_manager.get_function_at(origin_entry_point)
        to_func = self.to_function_manager.get_function_at(result_entry_point)

        if (from_func and to_func):
            from_name = from_func.name
            from_symbol = from_func.symbol
            from_source = from_symbol.source
            is_from_default_thunk = FunctionMerge.is_default_thunk(from_func)

            to_name = to_func.name
            to_symbol = to_func.symbol
            to_source = to_symbol.source
            is_to_default_thunk = FunctionMerge.is_default_thunk(to_func)

            if (is_from_default_thunk and is_to_default_thunk):
                return to_symbol

            from_namespace = self.from_program.get_global_namespace() if is_from_default_thunk else from_symbol.parent_namespace
            expected_to_namespace = DiffUtility.get_namespace(from_namespace, self.to_program)
            
            if not is_from_default_thunk and expected_to_namespace:
                existing_symbol = self.to_program.symbol_table.get_symbol(from_name, origin_entry_point, expected_to_namespace)

                if (existing_symbol):
                    if not existing_symbol.is_primary():
                        cmd = SetLabelPrimaryCmd(origin_entry_point, from_name, expected_to_namespace)
                        if cmd.apply_to(self.to_program):
                            existing_symbol = cmd.get_symbol()
                    
                    return existing_symbol

            current_to_namespace = self.to_program.get_global_namespace() if is_to_default_thunk else to_symbol.parent_namespace
            symbol_expected_namespace = SimpleDiffUtility.get_symbol(from_symbol.symbol, self.to_program)
            
            same_namespace = current_to_namespace == expected_to_namespace
            
            if (from_source == to_source and from_name == to_name and same_namespace):
                return to_symbol

            namespace_desired = current_to_namespace
            if not same_namespace:
                namespace_desired = new SymbolMerge(self.from_program, self.to_program).resolve_namespace(from_namespace, conflict_symbol_id_map)

            if (from_source != to_source or from_name != to_name or current_to_namespace != namespace_desired):
                to_symbol.set_name_and_namespace(from_name, namespace_desired, from_source)
            
            return to_func.symbol

        return None


    def replace_functions_names(self, origin_address_set, monitor=None):
        if monitor:
            monitor.set_message("Replacing function names...")
        
        origin_iter = self.from_function_manager.get_functions(origin_address_set, True)

        conflict_symbol_id_map = {}
        max_count = int(origin_address_set.num_addresses)
        count = 0

        while (origin_iter.has_next()):
            monitor.set_progress(count + 1)
            if monitor.check_cancelled():
                break
            
            origin_func = origin_iter.next()
            
            source_type_origin = origin_func.symbol.source
            entry_point = origin_func.entry_point
            result_entry_point = self.origin_to_result_translator.get_address(entry_point)

            to_function_manager = self.to_program.function_manager

            if (to_function_manager):
                to_func = to_function_manager.get_function_at(result_entry_point)
                
                if (to_func and source_type_origin == 'DEFAULT'):
                    continue
                
                if not to_func.name == origin_func.name:
                    try:
                        replace_function_symbol(origin_entry_point, conflict_symbol_id_map, monitor)
                    except DuplicateNameException as e:
                        pass
                    except InvalidInputException as e:
                        pass
                    except CircularDependencyException as e:
                        # TODO May want message to user if can't replace name.
                        pass

            count += 1
        
        if monitor:
            monitor.set_progress(max_count)

    @staticmethod
    def replace_functions_names(pgm_merge, address_set, monitor=None):
        result_program = pgm_merge.result_program
        origin_program = pgm_merge.origin_program
        from_function_manager = origin_program.function_manager
        to_function_manager = result_program.function_manager

        iter = to_function_manager.get_functions(address_set, True)
        
        conflict_symbol_id_map = {}
        max_count = address_set.num_addresses
        
        if monitor:
            monitor.set_message("Replacing function names...")
        
        count = 0

        while (iter.has_next()):
            monitor.set_progress(count + 1)
            
            if monitor.check_cancelled():
                break
            
            result_func = iter.next()
            
            entry_point = result_func.entry_point
            origin_func = from_function_manager.get_function_at(entry_point)

            if (origin_func and not result_func.name == origin_func.name):
                try:
                    replace_function_symbol(origin_program, result_program, entry_point, conflict_symbol_id_map, monitor)
                except DuplicateNameException as e:
                    pass
                except InvalidInputException as e:
                    pass
                except CircularDependencyException as e:
                    # TODO May want message to user if can't replace name.
                    pass

            count += 1
        
        if monitor:
            monitor.set_progress(max_count)

