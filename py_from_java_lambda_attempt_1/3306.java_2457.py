Here is the translation of the Java code into Python:

```Python
import textwrap

class DataTypePanel:
    def __init__(self, data_type):
        self.data_type = data_type
        self.create()

    def set_data_type(self, data_type):
        this.data_type = data_type
        self.textPane.setText("")

        if isinstance(data_type, Composite):
            self.format_composite_text((Composite) data_type)
        elif isinstance(data_type, Enum):
            self.format_enum_text((Enum) data_type)
        elif isinstance(data_type, TypeDef):
            self.format_typedef_text((TypeDef) data_type)
        elif isinstance(data_type, FunctionDefinition):
            self.format_function_def((FunctionDefinition) data_type)
        else:
            self.format_data_type(data_type)

    def create(self):
        self.textPane = JTextPane()
        doc = self.textPane.getStyledDocument()
        add(self.textPane, BorderLayout.CENTER)
        self.textPane.setEditable(False)

        path_attr_set = SimpleAttributeSet()
        name_attr_set = SimpleAttributeSet()
        source_attr_set = SimpleAttributeSet()
        offset_attr_set = SimpleAttributeSet()
        content_attr_set = SimpleAttributeSet()
        field_name_attr_set = SimpleAttributeSet()
        comment_attr_set = SimpleAttributeSet()

    def format_path(self, data_type):
        insert_string("Path: " + str(data_type.get_category_path()) + "\n\n", path_attr_set)

    def format_source_archive(self, data_type):
        source_archive = data_type.get_source_archive()
        universal_id = (source_archive is not None) and source_archive.get_source_archive_id() or None
        if universal_id == null:
            return "Local"
        else:
            return source_archive.name

    def format_alignment(self, composite):
        str = CompositeInternal.get_alignment_and_packing_string(composite)
        insert_string(str + "\n\n", source_attr_set)

    # ... (rest of the code remains similar in Python as well)