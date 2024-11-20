Here is the translation of the Java code into Python:

```Python
class DebuggerStaticMappingProvider:
    def __init__(self, plugin):
        self.plugin = plugin
        self.add_mapping_dialog = DebuggerAddMappingDialog()
        self.auto_wiring = AutoService.wire_services_consumed(plugin, self)
        self.icon = DebuggerResources.ICON_PROVIDER_MAPPINGS
        self.help_location = DebuggerResources.HELP_PROVIDER_MAPPINGS
        self.window_menu_group = DebuggerPluginPackage.NAME

    def set_mapping_service(self, mapping_service):
        add_mapping_dialog.set_mapping_service(mapping_service)

    def get_component(self):
        return main_panel

    def get_action_context(self, event):
        if my_action_context is None:
            return super().get_action_context(event)
        return my_action_context

    def load_mappings(self):
        self.mapping_table_model.clear()
        if current_trace is not None:
            manager = current_trace.get_static_mapping_manager()
            self.mapping_table_model.add_all_items(manager.get_all_entries())

    def build_main_panel(self):
        self.mapping_table = GTable(self.mapping_table_model)
        main_panel.add(ScrollablePanel(VerticalLayout(), [self.mapping_table]))
        self.mapping_filter_panel = GhidraTableFilterPanel(
            self.mapping_table, self.mapping_table_model
        )
        main_panel.add(self.mapping_filter_panel, BorderLayout.SOUTH)

    def create_actions(self):
        action_add = AddAction.builder(self.plugin).description("Add Mapping from Listing Selections").on_action(activated_add).build_and_install_local(self)
        action_remove = RemoveAction.builder(self.plugin).with_context(DebuggerStaticMappingActionContext).enabled_when(ctx => not ctx.get_selected_mappings().is_empty()).on_action(activated_remove).build_and_install_local(self)
        action_select_current = SelectRowsAction.builder(self.plugin).description("Select mappings by trace selection").enabled_when(ctx => current_trace is not None).on_action(activated_select_current).build_and_install_local(self)

    def activated_add(self, ignore):
        self.tool.show_dialog(self.add_mapping_dialog)
        if code_viewer_service and listing_service:
            prog_loc = code_viewer_service.get_current_location()
            trace_loc = listing_service.get_current_location()

            if prog_loc is not None and trace_loc is not None:
                prog_sel = code_viewer_service.get_current_selection()
                trace_sel = listing_service.get_current_selection()

                if prog_sel is not None and len(prog_sel) > 1 or trace_sel is not None and len(trace_sel) > 1:
                    return

                length = max(0, sum(len(range) for range in (prog_sel or []) + (trace_sel or [])))
                start_prog = min(map(lambda x: x.get_address(), prog_sel)) if prog_sel else prog_loc.get_address()
                start_trace = min(map(lambda x: x.get_address(), trace_sel)) if trace_sel else trace_loc.get_address()

                try:
                    self.add_mapping_dialog.set_values(
                        prog_loc.get_program(),
                        current_trace,
                        start_prog,
                        start_trace,
                        length,
                        Range.at_least(view.get_snap()),
                    )
                except AddressOverflowException as e:
                    Msg.show_error(self, None, "Add Mapping", f"Error populating dialog: {e}")

    def activated_remove(self, ctx):
        try:
            with UndoableTransaction.start(current_trace, "Remove Static Mappings", False) as tid:
                for mapping in ctx.get_selected_mappings():
                    mapping.get_mapping().delete()
            tid.commit()
        except Exception as e:
            Msg.show_error(self, None, "Remove Mapping", f"Error removing mappings: {e}")

    def activated_select_current(self, ignored):
        if listing_service and trace_manager and current_trace is not None:
            prog_sel = listing_service.get_current_selection()

            if prog_sel is not None and len(prog_sel) > 0:
                mapping_manager = current_trace.get_static_mapping_manager()
                selected_mappings = set(mapping_manager.find_all_overlapping(range, Range.singleton(trace_manager.get_current_snap())) for range in prog_sel)
                self.set_selected_mappings(selected_mappings)

    def set_selected_mappings(self, sel):
        DebuggerResources.set_selected_rows(sel, StaticMappingRow.get_mapping, self.mapping_table, self.mapping_filter_panel)

    def remove_old_listeners(self):
        if current_trace is not None:
            current_trace.remove_listener(self.listener)

    def add_new_listeners(self):
        if current_trace is not None:
            current_trace.add_listener(self.listener)

    def set_trace(self, trace):
        if current_trace == trace:
            return

        self.remove_old_listeners()
        self.current_trace = trace
        self.add_new_listeners()
        self.load_mappings()

        self.add_mapping_dialog.set_trace(trace)
```

Note that this is a direct translation of the Java code into Python.