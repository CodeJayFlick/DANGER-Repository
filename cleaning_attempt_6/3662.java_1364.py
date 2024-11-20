class DisassociateDataTypeAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Disassociate From Archive", plugin.get_name())
        set_popup_menu_data(MenuData(["Disassociate From Archive"], None, "Sync"))
        set_enabled(True)

    @staticmethod
    def is_enabled_for_context(context):
        if not isinstance(context, DataTypesActionContext):
            return False

        context_object = context.get_context_object()
        g_tree = GTree(context_object)
        selection_paths = g_tree.get_selection_paths()

        nodes = get_disassociatable_nodes(selection_paths)

        return len(nodes) > 0


    @staticmethod
    def get_disassociatable_nodes(paths):
        nodes = []
        for path in paths:
            node = get_disassociatable_node(path)
            if node is not None:
                nodes.append(node)

        return nodes

    @staticmethod
    def get_disassociatable_node(path):
        g_tree_node = GTreeNode(path.get_last_component())
        if isinstance(g_tree_node, DataTypeNode):
            data_type = g_tree_node.get_data_type()
            data_type_manager = data_type.get_data_type_manager()
            source_archive = data_type.get_source_archive()

            if (source_archive is None or
                    source_archive == BuiltInSourceArchive.INSTANCE or
                    source_archive.get_source_archive_id() == data_type_manager.get_universal_id()):
                return None

            return g_tree_node


    def action_performed(self, context):
        context_object = context.get_context_object()
        g_tree = GTree(context_object)
        selection_paths = g_tree.get_selection_paths()

        nodes = get_disassociatable_nodes(selection_paths)

        unmodifiable_dtm = list(map(lambda node: node.get_data_type().get_data_type_manager(), nodes)) \
            .filter(lambda dtm: not dtm.is_updatable()) \
            .find_any()

        if unmodifiable_dtm is not None:
            dtm = unmodifiable_dtm[0]
            DataTypeUtils.show_unmodifiable_archive_error_message(g_tree, "Disassociate Failed", dtm)
            return

        if not confirm_operation(nodes):
            return

        r = monitor -> do_disassociate(nodes, monitor)

        TaskBuilder("Disassociate From Archive", r).set_status_text_alignment(SwingConstants.LEADING) \
            .launch_modal()


    @staticmethod
    def confirm_operation(nodes):
        message = "This will permanently disassociate these datatypes" + str(len(nodes)) + " datatype(s)?"
        as_html = HTMLUtilities.wrap_as_html(message)
        result = OptionDialog.show_yes_no_dialog(plugin.get_tool().get_tool_frame(), "Confirm Disassociate", as_html)

        return result == OptionDialog.YES_OPTION


    @staticmethod
    def do_disassociate(nodes, monitor):
        data_types = list(map(lambda node: node.get_data_type(), nodes))

        provider = plugin.get_provider()
        g_tree = provider.get_g_tree()

        collapse_archive_nodes(g_tree)
        
        try:
            disassociate_types(data_types, monitor)
        except CancelledException as e:
            pass

        finally:
            g_tree.restore_tree_state()


    @staticmethod
    def disassociate_types(data_types, monitor):
        monitor.initialize(len(data_types))

        managers_to_types = {}
        for dt in data_types:
            if not dt.get_data_type_manager() in managers_to_types:
                managers_to_types[dt.get_data_type_manager()] = []

            managers_to_types[dt.get_data_type_manager()].append(dt)

        for entry in managers_to_types.items():
            manager, types = entry
            disassociate_managers_types(manager, types, monitor)


    @staticmethod
    def disassociate_managers_types(dtm, data_types, monitor):
        source_to_types = {}
        for dt in data_types:
            if not dt.get_source_archive() in source_to_types:
                source_to_types[dt.get_source_archive()] = []

            source_to_types[dt.get_source_archive()].append(dt)

        monitor.set_message("Disassociating types from " + str(dtm))
        monitor.initialize(len(data_types))

        handler = plugin.get_data_type_manager_handler()
        for entry in source_to_types.items():
            source, types = entry
            synchronizer = DataTypeSynchronizer(handler, dtm, source)
            disassociate(synchronizer, dtm, types, monitor)


    @staticmethod
    def disassociate(synchronizer, dtm, data_types, monitor):
        try:
            for dt in data_types:
                if not monitor.check_cancelled():
                    synchronizer.open_transactions()
                    dtm.disassociate(dt)
                    monitor.increment_progress(1)

            synchronizer.re_sync_out_of_sync_in_time_only_data_types()

        finally:
            synchronizer.close_transactions()


    @staticmethod
    def collapse_archive_nodes(tree):
        root = tree.get_view_root()
        archives = list(root.children())

        for archive in archives:
            tree.collapse_all(archive)


class GTree(GTreeNode):
    pass


class DataTypeNode(GTreeNode):
    pass


class BuiltInSourceArchive(SourceArchive):
    INSTANCE = None
