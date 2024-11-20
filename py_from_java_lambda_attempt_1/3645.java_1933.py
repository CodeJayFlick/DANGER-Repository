Here is the translation of the given Java code into Python:

```Python
class CreateCategoryAction:
    NEW_CATEGORY = "New Category"

    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Create Category", self.plugin.name)
        menu_data = MenuData(["New", "Category"], None, "Create")
        self.set_popup_menu_data(menu_data)
        self.description = "Creates a new category."
        self.enabled = True

    def is_add_to_popup(self, context):
        if not isinstance(context, DataTypesActionContext) or \
           (category_node := get_selected_category_node(context)) is None or \
           not category_node.is_enabled():
            return False
        if isinstance(category_node, BuiltInArchiveNode):
            return False
        return True

    def is_enabled_for_context(self, context):
        category_node = get_selected_category_node(context)
        return category_node is not None and category_node.is_modifiable()

    @staticmethod
    def get_selected_category_node(context):
        if not isinstance(context, DataTypesActionContext):
            return None
        gtree = context.get_context_object()
        selection_paths = gtree.selection_paths
        if len(selection_paths) != 1:
            return None
        node = selection_paths[0].last_path_component
        if not isinstance(node, CategoryNode):
            return None
        return node

    def action_performed(self, context):
        gtree = context.get_context_object()
        selection_paths = gtree.selection_paths
        category_node = selection_paths[0].last_path_component
        category = category_node.category
        archive_node = category_node.archive_node
        archive = archive_node.archive
        data_type_manager = archive.data_type_manager

        new_name = None
        transaction_id = data_type_manager.start_transaction("Create Category")
        try:
            new_name = get_unique_category_name(category)
            category.create_category(new_name)
        except InvalidNameException as ie:
            pass  # can't happen since we created a unique valid name.
        finally:
            data_type_manager.end_transaction(transaction_id, True)

        data_type_manager.flush_events()
        gtree.start_editing(category_node, new_name)

    @staticmethod
    def get_unique_category_name(parent):
        index = 1
        name = CreateCategoryAction.NEW_CATEGORY

        category = parent.get_category(name)
        while category is not None:
            name += str(index)
            index += 1
            category = parent.get_category(name)
        return name


class MenuData:
    def __init__(self, items=None, icon=None, tooltip=""):
        self.items = items if items else []
        self.icon = icon
        self.tooltip = tooltip

class CategoryNode:
    @property
    def is_enabled(self):
        pass  # implement this method in the actual class

    @property
    def category(self):
        pass  # implement this method in the actual class

    @property
    def archive_node(self):
        pass  # implement this method in the actual class


class DataTypesActionContext:
    def get_context_object(self):
        pass  # implement this method in the actual class

    @property
    def selection_paths(self):
        pass  # implement this methods in the actual class
```

Please note that you will need to replace `CategoryNode`, `DataTypesActionContext` and other classes with their actual implementations.