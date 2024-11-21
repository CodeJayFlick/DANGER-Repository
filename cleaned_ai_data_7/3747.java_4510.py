class DataTypeNode:
    def __init__(self, data_type):
        self.data_type = data_type
        self.name = data_type.get_name()
        self.display_text = self._get_current_display_text()

    @property
    def display_text(self):
        return self.__display_text

    @display_text.setter
    def display_text(self, value):
        if self.__display_text != value:
            self.__display_text = value
            self.fire_node_changed()

    def _get_current_display_text(self):
        base_display_text = self.data_type.get_name()
        
        local_id = self.data_type.get_data_type_manager().get_universal_id()
        source_archive = self.data_type.get_source_archive()
        if source_archive and not (source_archive.get_archive_type() == 'BUILT_IN' or 
                                   source_archive.get_source_archive_id() == local_id):
            return base_display_text + f" ({source_archive.get_name()})"
        
        return base_display_text

    def get_data_type(self):
        return self.data_type

    def __eq__(self, other):
        if not isinstance(other, DataTypeNode):
            return False
        return self.data_type == other.data_type and self.name == other.name

    def __lt__(self, other):
        if not isinstance(other, DataTypeNode):
            return True  # All nodes come after everything else
        return super().__lt__(other)

    @property
    def is_cut(self):
        return self.__is_cut

    @is_cut.setter
    def is_cut(self, value):
        if self.__is_cut != value:
            self.__is_cut = value
            self.fire_node_changed()

    def get_icon(self, expanded=False):
        icon = None
        if isinstance(self.data_type, BuiltInDataType):
            icon = DataTypeUtils.get_builtin_icon(self.is_cut)
        else:
            icon = DataTypeUtils.get_icon_for_data_type(self.data_type, self.is_cut)

        return icon

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, value):
        if self.name != value:
            try:
                self.data_type.set_name(value)
            except DuplicateNameException as e:
                Msg.show_error("Rename Failed", "Data Type by the name {} already exists in this category.".format(value))
            except InvalidNameException as e:
                msg = str(e) or f"Invalid name specified: {value}"
                Msg.show_error("Invalid Name Specified", msg)
            finally:
                self.data_type.get_data_type_manager().end_transaction()

    def get_tooltip(self):
        base_type = DataTypeUtils.get_base_data_type(self.data_type)
        last_change_time = base_type.get_last_change_time()
        if last_change_time > self.__tooltip_timestamp:
            self.__tooltip_text = None

        if not self.__tooltip_text:
            self.__tooltip_text = ToolTipUtils.get_tooltip_text(self.data_type)
            self.__tooltip_timestamp = last_change_time

        return self.__tooltip_text

    @property
    def tooltip_text(self):
        return self.__tooltip_text

    @tooltip_text.setter
    def tooltip_text(self, value):
        if self.__tooltip_text != value:
            self.__tooltip_text = value
            self.fire_node_changed()

    def is_leaf(self):
        return True

    def fire_node_changed(self):
        pass  # Implement this method to handle node changed event

    @property
    def use_highlight(self):
        return self.__use_highlight

    @use_highlight.setter
    def use_highlight(self, value):
        if self.__use_highlight != value:
            self.__use_highlight = value
            self.fire_node_changed()

    def has_custom_editor(self):
        base_data_type = DataTypeUtils.get_base_data_type(self.data_type)
        return isinstance(base_data_type, Composite) or \
               (isinstance(base_data_type, Enum) and not isinstance(self.data_type, FunctionDefinition)) or \
               has_custom_editor_for_base_data_type()

    @property
    def is_favorite(self):
        data_type_manager = self.data_type.get_data_type_manager()
        return data_type_manager.is_favorite(self.data_type)

    def set_node_cut(self, value):
        if self.__is_cut != value:
            self.__is_cut = value
            self.fire_node_changed()

    @property
    def is_modifiable(self):
        archive_node = self.get_archive_node()
        return archive_node and archive_node.is_modifiable()

    def get_archive_node(self):
        parent = self.get_parent()
        if not parent:
            return None  # could happen during tree mutations

        return (parent).get_archive_node()

    @property
    def can_delete(self):
        return True

    def data_type_status_changed(self):
        self.fire_node_changed()

    def fire_node_changed(self, *args):
        pass  # Implement this method to handle node changed event

    def get_tree(self):
        pass  # Implement this method to get the tree
