Here is the translation of the given Java code into equivalent Python:

```Python
class ApplyEnumsAsLabelsAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Create Labels From Enums", plugin.name)
        self.set_popup_menu_data(["Create Labels From Enums"], None, "VeryLast")
        self.setEnabled(True)

    @property
    def popup_menu_data(self):
        return {"menu_items": ["Create Labels From Enums"]}

    def is_enabled_for_context(self, context):
        if not isinstance(context, DataTypesActionContext):
            return False

        gtree = context.get_context_object()
        selection_paths = gtree.get_selection_paths()

        for path in selection_paths:
            node = path.get_last_component()
            if self.is_valid_node(node):
                return True
        return False

    def is_valid_node(self, node):
        if isinstance(node, DataTypeNode):
            data_type = node.data_type
            if isinstance(data_type, Enum):
                return True
        return False

    @property
    def name(self):
        return "Create Labels From Enums"

    def action_performed(self, context):
        dt_action_context = DataTypesActionContext(context)
        gtree = dt_action_context.get_context_object()
        program = dt_action_context.get_program()

        if not program:
            Msg.show_error("A suitable program must be open and activated before create labels from enums may be performed.")
            return

        apply_selected_enums_task = ApplySelectedEnumsTask(gtree, program)
        TaskLauncher(apply_selected_enums_task, gtree).start()


class ApplySelectedEnumsTask(Task):
    def __init__(self, gtree, program):
        super().__init__("Create Labels From Selected Enum Data Types", True, False, True)
        self.g_tree = gtree
        self.program = program

    @property
    def name(self):
        return "Create Labels From Selected Enum Data Types"

    def run(self, monitor):
        data_type_manager = self.program.get_data_type_manager()
        total_labels_created = 0
        some_already_existed = False
        failed_to_create_some = False

        transaction_id = -1
        commit = False
        try:
            # start a transaction
            transaction_id = data_type_manager.start_transaction("Create Labels From Selected Enum Data Types")

            selection_paths = self.g_tree.get_selection_paths()
            for path in selection_paths:
                node = path.get_last_component()
                if not isinstance(node, DataTypeNode):
                    continue

                dt_node = DataTypeNode(node)
                data_type = dt_node.data_type
                if not isinstance(data_type, Enum):
                    continue

                enum_dt = Enum(data_type)
                result = self.create_labels(enum_dt)

                total_labels_created += result.number_created
                some_already_existed |= result.some_already_existed
                failed_to_create_some |= result.failed_to_create_some_labels

            commit = True
        finally:
            # commit the changes
            data_type_manager.end_transaction(transaction_id, commit)

        if failed_to_create_some:
            Msg.show_warn("One or more labels couldn't be created from the Enum values.")
        else:
            message = f"Labels created: {total_labels_created}."
            if some_already_existed:
                message += " Some labels already exist."
            self.plugin.get_tool().set_status_info(message)


class CreateLabelResult:
    def __init__(self):
        self.number_created = 0
        self.some_already_existed = False
        self.failed_to_create_some_labels = False

# usage example
plugin = Plugin()
action = ApplyEnumsAsLabelsAction(plugin)
```

Please note that this is a direct translation of the given Java code into equivalent Python.