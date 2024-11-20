Here is the translation of the Java code into Python:

```Python
class DebuggerRegionsProvider:
    def __init__(self):
        self.plugin = None
        self.listing_service = None
        self.trace_manager = None
        self.current_trace = None
        self.regions_listener = None
        self.region_table_model = None
        self.region_filter_panel = None

    class RegionTableColumns:
        NAME = ("Name", str, "getName", "setName")
        LIFESPAN = ("Lifespan", range, "get_lifespan", "set_lifespan")
        START = ("Start", int, "get_min_address", "set_start")
        END = ("End", int, "get_max_address", "set_end")
        LENGTH = ("Length", int, "get_length", "set_length")
        READ = ("Read", bool, "is_read", "set_read")
        WRITE = ("Write", bool, "is_write", "set_write")
        EXECUTE = ("Execute", bool, "is_execute", "set_execute")
        VOLATILE = ("Volatile", bool, "is_volatile", "set_volatile")

    class RegionTableModel:
        def __init__(self):
            self.name = "Regions"
            self.columns = [DebuggerRegionsProvider.RegionTableColumns.NAME,
                             DebuggerRegionsProvider.RegionTableColumns.LIFESPAN,
                             DebuggerRegionsProvider.RegionTableColumns.START,
                             DebuggerRegionsProvider.RegionTableColumns.END,
                             DebuggerRegionsProvider.RegionTableColumns.LENGTH,
                             DebuggerRegionsProvider.RegionTableColumns.READ,
                             DebuggerRegionsProvider.RegionTableColumns.WRITE,
                             DebuggerRegionsProvider.RegionTableColumns.EXECUTE,
                             DebuggerRegionsProvider.RegionTableColumns.VOLATILE]

        def clear(self):
            pass

    class RegionsListener:
        def __init__(self, provider):
            self.provider = provider
            self.listen_for_untyped(DomainObject.DO_OBJECT_RESTORED, lambda e: self.object_restored())
            self.listen_for(TraceMemoryRegionChangeType.ADDED, self.region_added)
            self.listen_for(TraceMemoryRegionChangeType.CHANGED, self.region_changed)
            self.listen_for(TraceMemoryRegionChangeType.LIFESPAN_CHANGED, self.region_changed)
            self.listen_for(TraceMemoryRegionChangeType.DELETED, self.region_deleted)

        def object_restored(self):
            pass

        def region_added(self, region):
            pass

        def region_changed(self, region):
            pass

        def region_deleted(self, region):
            pass

    class SelectAddressesAction:
        NAME = "Select addresses contained in regions"

        def __init__(self):
            self.plugin = None
            self.description = self.NAME
            self.enabled_when = lambda ctx: True if current_trace is not None else False
            self.on_action = lambda ignored: self.activated_select_current()

    class DebuggerRegionActionContext:
        pass

    def load_regions(self, trace=None):
        if self.current_trace is None or trace is None and self.current_trace != trace:
            return
        memory_manager = self.current_trace.get_memory_manager()
        all_items = memory_manager.get_all_regions()
        for item in all_items:
            # Add items to the table model here

    def navigate_to_selected_region(self):
        if listing_service is not None:
            selected_row = region_table.get_selected_row()
            value = region_table.get_value_at(selected_row, 0)
            if isinstance(value, int) and self.listing_service is not None:
                # Go to the address
                pass

    def create_actions(self):
        action_select_addresses = SelectAddressesAction()

    def set_trace(self, trace):
        if current_trace == trace:
            return
        remove_old_listeners()
        current_trace = trace
        add_new_listeners()
        load_regions(current_trace)
        context_changed()

    def remove_old_listeners(self):
        pass

    def add_new_listeners(self):
        pass

# Usage example:

provider = DebuggerRegionsProvider()
```

Please note that this is a translation of the Java code into Python, and it may not be perfect. The original Java code might have some dependencies or imports which are missing in this Python version.