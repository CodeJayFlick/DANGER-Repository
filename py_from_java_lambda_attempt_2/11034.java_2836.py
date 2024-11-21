Here is a translation of your Java code into equivalent Python:

```Python
class ProjectDataTableModel:
    def __init__(self):
        self.project_data = None
        self.editing_on = False
        self.load_was_cancelled = False

    @property
    def load_was_cancelled(self):
        return self.load_was_cancelled

    def do_load(self, accumulator: list[DomainFileInfo], monitor) -> None:
        if self.project_data is not None:
            self.load_was_cancelled = True
            root_folder = self.project_data.get_root_folder()
            add_files(accumulator, root_folder, monitor)
            self.load_was_cancelled = False

    def add_files(self, accumulator: list[DomainFileInfo], folder, monitor) -> None:
        files = folder.get_files()
        for file in files:
            if monitor.check_canceled():
                break
            accumulator.append(DomainFileInfo(file))
        folders = folder.get_folders()
        for folder in folders:
            if monitor.check_canceled():
                break
            add_files(accumulator, folder, monitor)

    def create_table_column_descriptor(self) -> TableColumnDescriptor[DomainFileInfo]:
        descriptor = TableColumnDescriptor()

        descriptor.add_visible_column(DomainFileTypeColumn())
        descriptor.add_visible_column(DomainFileNameColumn())
        descriptor.add_visible_column(DomainFilePathColumn())
        descriptor.add_visible_column(ModificationDateColumn())

        app_specific_columns = find_app_specific_columns()
        for column in app_specific_columns:
            if isinstance(column, ProjectDataColumn):
                if column.is_default_column():
                    descriptor.add_visible_column(column)
                else:
                    descriptor.add_hidden_column(column)

        return descriptor

    @staticmethod
    def find_app_specific_columns() -> list[ProjectDataColumn]:
        instances = ClassSearcher.get_instances(ProjectDataColumn)
        columns = []
        for instance in instances:
            if isinstance(instance, ProjectDataColumn):
                columns.append(instance)
        return sorted(columns)

    @property
    def data_source(self) -> ProjectData:
        return self.project_data

    def refresh(self) -> None:
        model_data = self.get_model_data()
        for info in model_data:
            info.refresh()
        super().refresh()

    def set_project_data(self, project_data: ProjectData) -> None:
        self.project_data = project_data
        self.reload()

    @property
    def is_cell_editable(self):
        return self.editing_on

    def value_at(self, row_index: int, column_index: int) -> None:
        info = self.get_row_object(row_index)
        try:
            new_name = str(value)
            domain_file = info.get_domain_file()
            if not domain_file.name == new_name:
                domain_file.set_name(new_name)
        except (InvalidNameException | DuplicateFileException as e):
            Msg.show_error(self, None, "Rename Failed", f"Invalid name: {e.message}")
        except IOException as e:
            Msg.show_error(self, None, "Rename Failed",
                           f"There was a problem renaming the file:\n{e.message}", e)

    def set_editing_on(self, on) -> None:
        self.editing_on = on

class DomainFileTypeColumn(AbstractDynamicTableColumn[DomainFileInfo]):
    @property
    def column_name(self):
        return "Type"

    def get_value(self, row_object: DomainFileInfo, settings, data, services) -> DomainFileType:
        return row_object.get_domain_file_type()

    @property
    def preferred_width(self):
        return 25

class DomainFileNameColumn(AbstractDynamicTableColumn[DomainFileInfo]):
    @property
    def column_name(self):
        return "Name"

    def get_value(self, info: DomainFileInfo, settings, data, services) -> str:
        return info.get_display_name()

    @property
    def preferred_width(self):
        return 200

class ModificationDateColumn(AbstractDynamicTableColumn[DomainFileInfo]):
    @property
    def column_name(self):
        return "Modified"

    def get_value(self, info: DomainFileInfo, settings, data, services) -> date:
        return info.get_modification_date()

    @property
    def preferred_width(self):
        return 200

class DomainFilePathColumn(AbstractDynamicTableColumn[DomainFileInfo]):
    @property
    def column_name(self):
        return "Path"

    def get_value(self, info: DomainFileInfo, settings, data, services) -> str:
        return info.get_path()

    @property
    def preferred_width(self):
        return 200

class AbstractDynamicTableColumn[DomainFileInfo]:
    pass
```

This Python code is equivalent to your Java code.