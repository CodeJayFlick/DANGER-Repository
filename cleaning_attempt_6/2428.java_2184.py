class DBTraceProgramViewEquateTable:
    def __init__(self, program):
        self.program = program
        self.equate_manager = program.trace.get_equate_manager()

    @property
    def cache(self):
        return {equate: view for equate, view in zip(self.equate_manager.values(), (DBTraceProgramViewEquate(program, e) for e in self.equate_manager.values()))}

    def create_equate(self, name, value):
        try:
            with self.program.trace.lock_write():
                equate = self.equate_manager.create(name, value)
                view = DBTraceProgramViewEquate(self.program, equate)
                self.cache[equate] = view
                return view
        except Exception as e:
            print(f"An error occurred: {e}")

    def remove_equate(self, name):
        try:
            with self.program.trace.lock_write():
                equate = self.equate_manager.get_by_name(name)
                if equate is None:
                    return False
                del self.cache[equate]
                equate.delete()
                return True
        except Exception as e:
            print(f"An error occurred: {e}")

    def delete_address_range(self, start, end):
        try:
            with self.program.trace.lock_write():
                self.equate_manager.clear_references(self.program.snap, AddressRangeImpl(start, end))
        except Exception as e:
            print(f"An error occurred: {e}")

    @property
    def do_view_equate(self, equate):
        if equate is None:
            return None
        return DBTraceProgramViewEquate(self.program, equate)

    def get_equate(self, name):
        try:
            with self.program.trace.lock_read():
                return self.do_view_equate(self.equate_manager.get_by_name(name))
        except Exception as e:
            print(f"An error occurred: {e}")

    def get_equate(self, reference, opnd_position, value):
        try:
            with self.program(trace).lock_read():
                code_unit = self.program.top_code(reference)
                if code_unit is None:
                    return None
                equate = self.equate_manager.get_referenced_by_value(code_unit.start_snap(), reference, opnd_position, value)
                return self.do_view_equate(equate)
        except Exception as e:
            print(f"An error occurred: {e}")

    def get_equates(self, reference):
        try:
            with self.program(trace).lock_read():
                equates = []
                code_unit = self.program.top_code(reference)
                if code_unit is None:
                    return equates
                for equate in self.equate_manager.get_referenced(code_unit.start_snap(), reference):
                    equates.append(self.do_view_equate(equate))
            return equates
        except Exception as e:
            print(f"An error occurred: {e}")

    def get_equates(self, value):
        try:
            with self.program(trace).lock_read():
                equates = []
                for equate in self.equate_manager.get_by_value(value):
                    equates.append(self.do_view_equate(equate))
            return equates
        except Exception as e:
            print(f"An error occurred: {e}")

    def get_equates(self):
        try:
            with self.program(trace).lock_read():
                return [self.do_view_equate(equate) for equate in self.equate_manager.values()]
        except Exception as e:
            print(f"An error occurred: {e}")

    def get_equate_addresses(self, start=None):
        if start is None:
            try:
                with self.program(trace).lock_read():
                    return self.program.viewport.unioned_addresses(s -> self.equate_manager.get_referring_addresses(Range.singleton(s))).get_addresses(True)
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            try:
                with self.program(trace).lock_read():
                    return self.program.viewport.unioned_addresses(s -> self.equate_manager.get_referring_addresses(Range.singleton(s))).get_addresses(start, True)
            except Exception as e:
                print(f"An error occurred: {e}")

    def get_equate_addresses(self, address_set_view):
        try:
            with self.program(trace).lock_read():
                return IntersectionAddressSetView(address_set_view, self.program.viewport.unioned_addresses(s -> self.equate_manager.get_referring_addresses(Range.singleton(s)))).get_addresses(True)
        except Exception as e:
            print(f"An error occurred: {e}")
