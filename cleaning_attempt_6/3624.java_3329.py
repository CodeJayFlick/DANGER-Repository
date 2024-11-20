class CycleGroupAction:
    def __init__(self, cycle_group, plugin):
        self.plugin = plugin
        self.cycle_group = cycle_group

    def init_key_stroke(self, key_stroke):
        if key_stroke is None:
            return
        set_key_binding_data(KeyBindingData(key_stroke))

    @property
    def keybindingdata(self):
        # This property should be implemented in the actual Python code.
        pass

    def dispose(self):
        self.cycle_group = None
        self.plugin = None
        super().dispose()

    def is_enabled_for_context(self, context):
        if isinstance(context.get_context_object(), ListingActionContext):
            return self.plugin.is_create_data_allowed(context)
        return False

    def action_performed(self, context):
        if context:
            context_obj = context.get_context_object()
            if isinstance(context_obj, ListingActionContext):
                program_context_obj = context_obj
                cycle_data(program_context_obj)

    def cycle_data(self, listing_action_context):
        listing = listing_action_context.get_program().get_listing()
        selection = listing_action_context.get_selection()
        location = listing_action_context.get_location()

        if selection and not selection.is_empty():
            cmd = None
            dt = None
            addr = selection.min_address
            data = listing.get_data_containing(addr)
            int_sel = selection.interior_selection

            if int_sel is None:
                dt = self.cycle_group.next_data_type(data.data_type, True)
                if dt is not None:
                    cmd = CreateDataBackgroundCmd(selection, dt)

            else:
                from_path = int_sel.from_.get_component_path()
                length = len(selection)
                comp_data = data.get_component(from_path)
                if comp_data is None:
                    return
                dt = self.cycle_group.next_data_type(comp_data.data_type, True)
                if dt is not None:
                    cmd = CreateDataInStructureBackgroundCmd(addr, from_path, length, dt)

            if len(selection) < DataPlugin.background_selection_threshold:
                plugin_tool = self.plugin.get_plugin_tool()
                plugin_tool.execute(cmd, listing_action_context.get_program())
            else:
                plugin_tool.execute_background_command(cmd, listing_action_context.get_program())

        elif location is not None:
            addr = location.address
            data = listing.get_data_containing(addr)
            if data is None:
                return

            comp_path = location.component_path
            if comp_path and len(comp_path) > 0:
                dt = self.cycle_group.next_data_type(data.data_type, True)
                if dt is not None:
                    plugin_tool.execute(CreateDataCmd(addr, dt, True, False), listing_action_context.get_program())
                    self.plugin.update_recently_used(dt)

            else:
                comp_data = data.get_component(comp_path)
                if comp_data is not None:
                    dt = self.cycle_group.next_data_type(comp_data.data_type, True)
                    if dt is not None:
                        plugin_tool.execute(CreateDataInStructureCmd(addr, comp_path, dt), listing_action_context.get_program())
                        self.plugin.update_recently_used(dt)

class CreateDataBackgroundCmd:
    def __init__(self, selection, data_type):
        pass

class CreateDataInStructureBackgroundCmd:
    def __init__(self, addr, from_path, length, data_type):
        pass
