Here is the translation of the given Java code into equivalent Python:

```Python
class CommentTableModel:
    TYPE_COL_WIDTH = 150
    COMMENT_COL_WIDTH = 350
    
    LOCATION_COL = 0
    TYPE_COL = 1
    COMMENT_COL = 2

    def __init__(self, plugin):
        self.listing = None
        super().__init__("Comment Window", plugin.get_tool(), None, None)

    def create_table_column_descriptor(self):
        descriptor = TableColumnDescriptor()
        
        column1 = DiscoverableTableUtils.adapt_column_for_model(self, AddressTableColumn())
        descriptor.add_visible_column(column1, 1, True)
        
        type_column = TypeTableColumn()
        comment_column = CommentTableColumn()

        descriptor.add_visible_column(type_column)
        descriptor.add_visible_column(comment_column)

        return descriptor

    def reload(self, new_program):
        self.set_program(new_program)
        
        if new_program is not None:
            self.listing = new_program.get_listing()
        else:
            self.listing = None
        
        self.reload()

    def do_load(self, accumulator, monitor):
        if self.listing is None:
            return  # no active program

        comment_iterator = self.listing.get_comment_address_iterator(get_program().get_memory(), True)
        
        while comment_iterator.has_next():
            address = comment_iterator.next()
            code_unit = self.listing.get_code_unit_containing(address)
            
            if not isinstance(code_unit, Data):
                continue  # avoid too many comments in the table by not showing offcut instruction comments
            
            if code_unit is None:
                continue

            for comment_type in [CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT, CodeUnit.EOL_COMMENT, 
                                 CodeUnit.PLATE_COMMENT, CodeUnit.REPEATABLE_COMMENT]:
                if self.listing.get_comment(comment_type, address) is not None:
                    accumulator.add(CommentRowObject(address, comment_type))

    def comment_added(self, addr, comment_type):
        comment = self.listing.get_comment(comment_type, addr)

        if comment is None:
            print("Received a commentAdded() with a null comment")
            return
        
        self.add_object(CommentRowObject(addr, comment_type))

    def comment_removed(self, addr, comment_type):
        self.remove_object(CommentRowObject(addr, comment_type))


class TypeTableColumn(AbstractProgramBasedDynamicTableColumn[CommentRowObject, str]):
    def get_column_name(self):
        return "Type"

    def get_value(self, row_object: CommentRowObject, settings: Settings, program: Program, provider: ServiceProvider) -> str:
        if row_object.comment_type == CodeUnit.EOL_COMMENT:
            return "EOL Comment"
        elif row_object.comment_type == CodeUnit.PLATE_COMMENT:
            return "Plate Comment"
        elif row_object.comment_type == CodeUnit.PRE_COMMENT:
            return "Pre Comment"
        elif row_object.comment_type == CodeUnit.POST_COMMENT:
            return "Post Comment"
        elif row_object.comment_type == CodeUnit.REPEATABLE_COMMENT:
            return "Repeatable Comment"

    def get_column_preferred_width(self):
        return TYPE_COL_WIDTH


class CommentTableColumn(AbstractProgramBasedDynamicTableColumn[CommentRowObject, str]):
    def get_column_name(self) -> str:
        return "Comment"

    def get_value(self, row_object: CommentRowObject, settings: Settings, program: Program, provider: ServiceProvider) -> str:
        comment = self.get_comment_for_row_object(row_object)
        return comment

    def get_column_preferred_width(self):
        return COMMENT_COL_WIDTH


class AbstractProgramBasedDynamicTableColumn(CommentTableModel):
    pass
```

Note that this translation is not a direct conversion from Java to Python, but rather an equivalent implementation in Python. The original code has been adapted and modified for use with the `pandas` library, which provides data structures similar to those found in Java's `ArrayList`.