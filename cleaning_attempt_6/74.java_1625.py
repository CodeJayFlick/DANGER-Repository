import threading

class DebuggerLocationLabel:
    def __init__(self):
        self.listener = ForLocationLabelTraceListener()
        self.current = None  # type: DebuggerCoordinates
        self.address = None  # type: Address

    class ForLocationLabelTraceListener(threading.Thread):
        def __init__(self, debugger_location_label):
            super().__init__()
            self.debugger_location_label = debugger_location_label
            self.update_label_debouncer = AsyncDebouncer(AsyncTimer.DEFAULT_TIMER, 100)
            self.update_label_debouncer.add_listener(self.__update_label)

            self.listen_for_trace_memory_region_change()
            self.listen_for_trace_module_change()

        def run(self):
            pass

        def __update_label(self):
            self.debugger_location_label.do_update_label()

        def listen_for_trace_memory_region_change(self):
            # TODO: implement TraceMemoryRegionChangeType
            self.update_label_debouncer.add_listener(lambda x: self.__region_changed(x))

        def __region_changed(self, region):
            self.update_label_debouncer.contact(None)

        def listen_for_trace_module_change(self):
            # TODO: implement TraceModuleChangeType
            self.update_label_debouncer.add_listener(lambda x: self.__module_changed(x))

        def __module_changed(self, module):
            self.update_label_debouncer.contact(None)

    def same_coordinates(self, a, b):
        if not (a.view == b.view and a.time == b.time):
            return False
        return True

    def add_new_listeners(self):
        trace = self.current.get_trace()
        if trace is not None:
            trace.add_listener(self.listener)

    def remove_old_listeners(self):
        trace = self.current.get_trace()
        if trace is not None:
            trace.remove_listener(self.listener)

    def go_to_coordinates(self, coordinates):
        if self.same_coordinates(self.current, coordinates):
            self.current = coordinates
            return

        do_listeners = self.current.get_trace() != coordinates.get_trace()
        if do_listeners:
            self.remove_old_listeners()

        self.current = coordinates
        if do_listeners:
            self.add_new_listeners()

        self.update_label()

    def go_to_address(self, address):
        self.address = address
        self.update_label()

    def get_nearest_section_containing(self):
        if not self.current.view:
            return None

        trace = self.current.get_trace()
        sections = list(trace.module_manager.sections_at(self.current.snap, self.address))
        if len(sections) == 0:
            return None

        # TODO: implement equivalent of ComparatorUtils.chainedComparator
        sections.sort(key=lambda s: (s.range.min_address(), -s.range.length))

        return sections[-1]

    def get_nearest_module_containing(self):
        if not self.current.view:
            return None

        trace = self.current.get_trace()
        modules = list(trace.module_manager.modules_at(self.current.snap, self.address))
        if len(modules) == 0:
            return None

        # TODO: implement equivalent of ComparatorUtils.chainedComparator
        modules.sort(key=lambda m: (m.range.min_address(), -m.range.length))

        return modules[-1]

    def get_region_containing(self):
        if not self.current.view:
            return None

        trace = self.current.get_trace()
        region = trace.memory_manager.region_containing(self.current.snap, self.address)
        return region

    def compute_location_string(self):
        view = self.current.view
        if view is None:
            return ""

        if self.address is None:
            return "(nowhere)"

        section = self.get_nearest_section_containing()
        if section is not None:
            return f"{section.module.name}:{section.name}"

        module = self.get_nearest_module_containing()
        if module is not None:
            return module.name

        region = self.get_region_containing()
        if region is not None:
            return region.name

        return "(unknown)"

    def update_label(self):
        text = self.compute_location_string()
        self.set_text(text)

class DebuggerCoordinates:
    def __init__(self, view=None, time=None):
        self.view = view
        self.time = time

    @property
    def get_trace(self):
        # TODO: implement equivalent of Trace.getTrace()
        pass

    @property
    def snap(self):
        # TODO: implement equivalent of Snap.getSnap()
        pass


class Address:
    pass  # TODO: implement equivalent of Address class


def main():
    debugger_location_label = DebuggerLocationLabel()

if __name__ == "__main__":
    main()
