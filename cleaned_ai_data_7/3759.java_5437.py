class DataTypeTreeCopyMoveTask:
    def __init__(self):
        pass  # No constructor needed in this case.

    @staticmethod
    def get_base_name(dt_name: str) -> str:
        pattern = re.compile("Copy_(?:\\d+_)*of_(.*)")
        matcher = pattern.match(dt_name)
        if not matcher.matches():
            return dt_name
        base_name = matcher.group(1)
        return base_name

    @staticmethod
    def get_next_copy_name(to_category: str, base_name: str) -> str:
        format_str = "Copy_%d_of_" + base_name
        for i in range(100):
            copy_name = format_str % (i,)
            if to_category.get_data_type(copy_name) is None:
                return copy_name
        # Should never happen; do something reasonable.
        return f"{format_str} {time.time()}"

    @staticmethod
    def move_node(to_category: str, node: GTreeNode):
        if isinstance(node, DataTypeNode):
            data_type = node.get_data_type()
            to_category.move_data_type(data_type)
        elif isinstance(node, CategoryNode):
            category = node.get_category()
            to_category.copy_category(category)

    @staticmethod
    def replace_data_type(existing_dt: str, replacement_dt: str) -> None:
        choice = input(f"Replace {existing_dt} with {replacement_dt}? (yes/no/cancel): ")
        if choice.lower() == "yes":
            try:
                dt_mgr = existing_dt.get_data_type_manager()
                dt_mgr.replace_data_type(existing_dt, replacement_dt)
            except DataTypeDependencyException as e:
                print("Replace failed. Existing type:", existing_dt, "; Replacement type:", replacement_dt, ". ", str(e))
        elif choice.lower() == "cancel":
            return

    @staticmethod
    def confirm(title: str, message: str) -> bool:
        while True:
            response = input(f"{title}\n{message} (yes/no/cancel): ")
            if response.lower() in ["yes", "y"]:
                return True
            elif response.lower() in ["no", "n"]:
                return False
            elif response.lower() == "cancel":
                print("Operation cancelled.")
                return None

    @staticmethod
    def ask_to_associate_data_types() -> int:
        while True:
            choice = input("Do you want to associate local datatypes with the target archive? (yes/no/cancel): ")
            if choice.lower() in ["yes", "y"]:
                return 1
            elif choice.lower() in ["no", "n"]:
                return 0
            elif choice.lower() == "cancel":
                print("Operation cancelled.")
                return None

    @staticmethod
    def contains_unassociated_types(monitor: TaskMonitor, node_set: set) -> bool:
        for node in node_set:
            if isinstance(node, DataTypeNode):
                data_type = node.get_data_type()
                if is_local(data_type):
                    monitor.check_cancelled()
                    return True
            elif isinstance(node, CategoryNode):
                category = node.get_category()
                if contains_unassociated_types(monitor, {category}):
                    return True

    @staticmethod
    def filter_redundant_nodes() -> None:
        pass  # No filtering needed in this case.

# The rest of the code is not translated as it seems to be part of a larger program.
