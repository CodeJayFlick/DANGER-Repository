class SetLabelPrimaryCmd:
    def __init__(self, addr, name, namespace):
        self.addr = addr
        self.name = name
        self.namespace = namespace

    def apply_to(self, obj):
        program = Program(obj)
        st = program.get_symbol_table()
        old_symbol = st.get_primary_symbol(addr)

        if old_symbol is None:
            return False, "No Symbols at address: {}".format(addr)

        if namespace is None:
            namespace = program.get_global_namespace()

        symbol = st.get_symbol(name, addr, namespace)
        if symbol is None:
            if not old_symbol.is_dynamic():
                return False, "Symbol {} does not exist in namespace {} at address {}".format(
                    name, namespace, addr
                )
            else:
                return True

        if old_symbol.symbol_type == SymbolType.FUNCTION:
            if old_symbol == symbol:
                return True  # function symbol is already primary

            # keep the function symbol and rename it to the new symbol name;
            # (first have to delete the new symbol).
            old_name = old_symbol.name
            old_source = old_symbol.source
            old_parent = old_symbol.parent_namespace
            if namespace == old_symbol.object:
                # local label promotion - switch names but not namespaces
                old_parent = namespace
                namespace = old_symbol.parent_namespace

            try:
                symbol.delete()
                old_symbol.set_name_and_namespace(name, namespace, old_source)
                return True  # If renamed oldSymbol is now Default source don't keep old name (handles special Thunk rename case)

            except DuplicateNameException as e:
                return False, "Duplicate name should not have happened for {}".format(name)

            except InvalidInputException as e:
                return False, "InvalidInputException: {}".format(e.message())

            except CircularDependencyException as e:
                return False, "CircularDependencyException: {}".format(e.message())
        else:
            if not symbol.set_primary():
                return False, "Set primary not permitted for {}".format(symbol.name)

        return True

    def get_status_msg(self):
        return self.error_msg

    def get_name(self):
        return "Set Primary Label"

    def get_symbol(self):
        return self.symbol
