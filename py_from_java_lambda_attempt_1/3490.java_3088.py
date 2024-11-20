Here is the translation of the given Java code into Python:

```Python
class ClearCmd:
    EVENT_LIMIT = 1000

    def __init__(self, cu=None, options=None):
        self.view = None
        self.options = options
        self.send_individual_events = False

    @staticmethod
    def get_name():
        return "Clear with Options" if options else "Clear code"

    def apply_to(self, obj, monitor):
        was_enabled = obj.is_sending_events()
        try:
            obj.set_events_enabled(send_individual_events)
            result = self.do_apply_to(obj, monitor)
            return result
        finally:
            obj.set_events_enabled(was_enabled)

    def do_apply_with_cancel(self, obj, monitor):
        if not monitor:
            monitor = TaskMonitorAdapter.DUMMY_MONITOR

        program = Program(obj)
        if options is None:
            self.clear_code(program, view, monitor)
            return True
        elif options.clear_equates():
            self.clear_equates(program, view, monitor)
        elif options.clear_code():
            self.clear_code(program, view, monitor)
        elif options.clear_comments():
            self.clear_comments(program, view, monitor)
        elif options.clear_functions():
            self.clear_functions(program, view, monitor)
        elif options.clear_symbols():
            self.clear_symbols(program, view, monitor)
        elif options.clear_properties():
            self.clear_properties(program, view, monitor)
        elif options.clear_registers():
            self.clear_registers(program, view, monitor)
        if reference_source_types_to_clear:
            self.clear_references(program, view, reference_source_types_to_clear, monitor)

    def do_apply_to(self, obj, monitor):
        try:
            return self.do_apply_with_cancel(obj, monitor)
        except CancelledException as e:
            return True

    @staticmethod
    def clear_code(program, address_set_view, task_monitor):
        listing = program.get_listing()
        if not address_set_view.is_empty():
            for range in address_set_view.get_address_ranges():
                start = range.min_address
                end = range.max_address
                self.clear_addresses(task_monitor, listing, start, end)

    @staticmethod
    def clear_equates(program, view, task_monitor):
        equate_table = program.get_equate_table()
        if not view.is_empty():
            for eq in equate_table.get_equates():
                refs = eq.get_references()
                for ref in refs:
                    if view.contains(ref.address):
                        eq.remove_reference(ref.address, ref.op_index)
                if len(eq.get_references()) == 0:
                    equate_table.remove_equate(eq.name)

    @staticmethod
    def clear_comments(program, address_set_view, task_monitor):
        listing = program.get_listing()
        if not address_set_view.is_empty():
            for range in address_set_view.get_address_ranges():
                start = range.min_address
                end = range.max_address
                self.clear_addresses(task_monitor, listing, start, end)

    @staticmethod
    def clear_properties(program, view, task_monitor):
        listing = program.get_listing()
        if not view.is_empty():
            for range in address_set_view.get_address_ranges():
                start = range.min_address
                end = range.max_address
                self.clear_addresses(task_monitor, listing, start, end)

    @staticmethod
    def clear_functions(program, view, task_monitor):
        function_manager = program.get_function_manager()
        if not view.is_empty():
            for func in function_manager.get_functions(view, True):
                monitor.increment_progress(1)
                function_manager.remove_function(func.entry_point())

    @staticmethod
    def clear_registers(program_context, address_range, task_monitor):
        chunker = AddressRangeChunker(address_range.min_address, address_range.max_address, 10000)
        for range in chunker:
            min_addr = range.min_address
            max_addr = range.max_address
            monitor.set_message("Clearing code at " + str(min_addr))
            program_context.clear_code_units(min_addr, max_addr)

    @staticmethod
    def clear_references(program, view, reference_source_types_to_clear, task_monitor):
        if not view.is_empty():
            for addr in view.get_addresses():
                refs = program.get_reference_manager().get_references_from(addr)
                for ref in refs:
                    source_type = ref.source()
                    if reference_source_types_to_clear.contains(source_type):
                        program.get_reference_manager().delete(ref)

    @staticmethod
    def clear_bookmarks(program, address_set_view, task_monitor):
        bookmark_manager = program.get_bookmark_manager()
        if not view.is_empty():
            for addr in view.get_addresses():
                bookmark_manager.remove_bookmarks(addr)
```

Please note that Python does not have direct equivalent of Java's try-finally block. However, you can achieve similar functionality using a `try-except` block and the `finally` clause is not available directly but it can be achieved by putting your code in an outer function with a return statement at the end.

Also, Python doesn't support multi-threading like Java does.