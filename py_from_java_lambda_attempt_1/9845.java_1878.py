Here is the translation of the Java code into Python:

```Python
class TableColumnModelState:
    LARGE_DEFAULT_COL_WIDTH = 500
    
    def __init__(self, table, column_model):
        self.table = table
        self.column_model = column_model
        
        # Create update managers for saving and restoring state
        self.save_update_manager = SwingUpdateManager(SAVE_DELAY, lambda: self.do_save_state())
        self.restore_update_manager = SwingUpdateManager(250, lambda: self.do_restore_state())

    def install_sort_listener(self):
        if isinstance(table.model, SortedTableModel):
            sorted_model = table.model
            sorted_model.add_sort_listener(self)

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        self._enabled = value

    def model_sorted(self, sort_state):
        if sort_state == self.last_sort_state:
            return
        
        self.last_sort_state = sort_state
        self.save_state()

    def save_state(self):
        if not self.restoring and self.enabled:
            self.save_update_manager.update_later()
    
    def do_save_state(self):
        if self.restore_update_manager.is_busy():
            # Don't save while there is a pending restore operation, as we want to save the state of the table after being restored
            self.save_update_manager.update_later()
            return
        
        self.do_save_state(self.save_to_xml())

    def do_save_state(self, xml_element):
        preference_state = PreferenceState()
        preference_state.put_xml_element(XML_COLUMN_DATA, xml_element)

        docking_window_manager = DockingWindowManager.get_instance(table)
        if docking_window_manager is None:
            # I don't think this can happen now, as we ignore save requests when not 'enabled'
            return
        
        preference_key = self.preference_key()
        docking_window_manager.put_preference_state(preference_key, preference_state)

    def save_to_xml(self):
        xml_element = Element("Table_State")

        column_list = self.column_model.get_all_columns()
        for column in column_list:
            element = Element(XML_COLUMN)
            element.set_attribute(XML_COLUMN_NAME, get_column_name(column))
            element.set_attribute(XML_COLUMN_WIDTH, str(column.width()))
            element.set_attribute(XML_COLUMN_VISIBLE,
                                   str(self.column_model.is_visible(column)))
            save_column_settings(element, column)

            xml_element.add_content(element)

        self.save_sorted_column_state(xml_element)
        
        return xml_element

    def get_preference_key(self):
        preference_key = table.get_preference_key()
        if preference_key is not None:
            return preference_key
        
        model_name = type(table.model).__name__
        buffer = StringBuffer()
        buffer.append(model_name + ":")
        for i in range(len(column_list)):
            column_name = self.column_model.get_column_name(i)
            buffer.append(column_name + ":")
        
        return buffer.toString()

    def set_default_columns_visible(self):
        model = table.get_unwrapped_table_model()
        if isinstance(model, VariableColumnTableModel):
            variable_model = model
            num_visible = 0
            for column in self.column_model.get_all_columns():
                model_index = column.model_index
                is_visible = variable_model.is_visible_by_default(model_index)
                self.column_model.set_visible(column, is_visible)
                if is_visible:
                    num_visible += 1
            
            if num_visible == 0:  # Make sure at least one column is visible.
                self.column_model.set_visible(self.column_model.get_all_columns()[0], True)

        set_default_preferred_column_sizes()

    def set_default_preferred_column_sizes(self):
        model = table.get_unwrapped_table_model()
        if isinstance(model, AbstractGTableModel):
            g_model = model
            for column in self.column_model.get_all_columns():
                default_preferred = column.preferred_width
                if default_preferred > 0 and default_preferred != 75:
                    # Honor any saved preferred size (ignoring the magic default value found inside of TableColumn)
                    column.width = default_preferred
                    continue
                
                preferred = g_model.get_preferred_column_width(column.model_index)
                if preferred < 15:
                    preferred = LARGE_DEFAULT_COL_WIDTH
                size = preferred
                column.width = size
                column.preferred_width = size

    def dispose(self):
        self.save_update_manager.dispose()
        self.restore_update_manager.dispose()

class PreferenceState:
    def put_xml_element(self, key, value):
        pass
    
    def get_xml_element(self, key):
        pass

class SwingUpdateManager:
    def __init__(self, delay, callback):
        self.delay = delay
        self.callback = callback
        self.is_busy = False
    
    def update_later(self):
        if not self.is_busy:
            self.is_busy = True
            Timer(delay=self.delay, target=self.callback).start()
    
    def is_busy(self):
        return self.is_busy
    
    def dispose(self):
        pass

class Element:
    def __init__(self, name):
        self.name = name
    
    def set_attribute(self, key, value):
        pass
    
    def add_content(self, element):
        pass
```

Please note that Python does not have direct equivalents for Java's Swing and XML-related classes. The above code is a translation of the provided Java code into equivalent Python constructs.