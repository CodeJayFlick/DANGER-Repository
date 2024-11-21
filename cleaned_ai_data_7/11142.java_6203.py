class ProjectDataRenameAction:
    icon = ResourceManager.load_image("images/page_edit.png")

    def __init__(self, owner, group):
        super().__init__("Rename", owner)
        self.set_popup_menu_data(MenuData(["Rename"], icon, group))
        self.mark_help_unnecessary()

    @property
    def is_enabled_for_context(self) -> bool:
        if not context.has_exactly_one_file_or_folder():
            return False

        if context.file_count == 1:
            file = context.get_selected_files()[0]
            if file.is_read_only():
                return False

        else:
            folder = context.get_selected_folders()[0]
            if folder.parent is None:  # can't rename root folder
                return False

        if context.read_only_project:
            return False

        return True

    def actionPerformed(self, context):
        if context.file_count == 1:
            file = context.get_selected_files()[0]

            if not file.is_checked_out():
                if not file.consumers or not file.busy:
                    component = context.component
                    if isinstance(component, DataTree):
                        tree = component
                        node = context.context_object
                        tree.set_editable(True)
                        tree.start_editing(node.parent, node.name)

                    elif isinstance(component, GTable):
                        table = component
                        info = context.context_object
                        model = table.model
                        data = model.data
                        index_of = data.index(info)
                        if index_of >= 0:
                            model.set_editing(True)
                            table.edit_cell_at(index_of, self.find_name_column(table))
                            model.set_editing(False)

    def find_name_column(self, table):
        model = table.column_model
        column_count = model.get_column_count()
        for col in range(column_count):
            column = model.get_column(col)
            if "Name" == str(column.header_value):
                return col

        return 0


class ResourceManager:
    @staticmethod
    def load_image(image_name: str) -> Icon:
        # implement your logic here to load the image
        pass
