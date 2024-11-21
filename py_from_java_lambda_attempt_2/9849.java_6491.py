Here is the translation of the Java code into Python:

```Python
class TableModelWrapper:
    def __init__(self, wrapped_model):
        self.wrapped_model = wrapped_model
        self.filtered_index_list = get_matching_filtered_indices()
        
    @property
    def name(self):
        return self.wrapped_model.name

    @property
    def last_selected_objects(self):
        return self.last_selected_objects
    
    @last_selected_objects.setter
    def last_selected_objects(self, value):
        self.last_selected_objects = value
        
    @property
    def table_filter(self):
        return self.table_filter
    
    @table_filter.setter
    def table_filter(self, value):
        self.table_filter = value
        update_model()
        
    def get_name(self):
        return self.wrapped_model.get_name()

    def set_last_selected_objects(self, value):
        self.last_selected_objects = value
        
    def is_filtered(self):
        return len(self.filtered_index_list) != self.wrapped_model.get_row_count()

    def add_table_model_listener(self, l):
        self.listeners.add(l)
        
    def remove_table_model_listener(self, l):
        self.listeners.remove(l)

    @property
    def column_class(self):
        return self.wrapped_model.column_class

    @property
    def column_count(self):
        return self.wrapped_model.get_column_count()

    @property
    def get_column_name(self):
        return self.wrapped_model.get_column_name

    @property
    def row_count(self):
        if not is_filtered():
            return self.wrapped_model.get_row_count()
        
        return len(self.filtered_index_list)

    @property
    def unfiltered_row_count(self):
        return self.wrapped_model.get_row_count()

    @property
    def model_data(self):
        if not is_filtered():
            return self.unfiltered_model_data
        
        list = []
        for row in range(len(filtered_index_list)):
            index = filtered_index_list[row]
            list.append(wrapped_model.get_row_object(index))
        
        return list

    @property
    def get_unfiltered_model_data(self):
        return self.wrapped_model.model_data

    def set_table_filter(self, value):
        if not is_filtered():
            update_model()
            
    def fire_table_data_changed(self):
        for listener in listeners:
            listener.table_changed()

    def wrapped_model_changed_from_table_changed_event(self):
        update_filter_indices()

    def get_matching_filtered_indices(self):
        list = []
        row_count = self.wrapped_model.get_row_count

        for model_row in range(row_count):
            if filter_accepts_row(model_row):
                list.append(model_row)
        
        return list

    def filter_accepts_row(self, model_row):
        if not table_filter:
            return True
        
        row_object = wrapped_model.get_row_object(model_row)
        accepts = table_filter.accepts_row(row_object)
        return accepts

    def update_model(self):
        self.update_filter_indices()
        
        fire_table_data_changed()

    def update_filter_indices(self):
        self.filtered_index_list = get_matching_filtered_indices()

def main():
    # Example usage
    wrapped_model = RowObjectTableModel()  # Assuming this class exists in Python
    table_model_wrapper = TableModelWrapper(wrapped_model)
    
if __name__ == "__main__":
    main()
```

Please note that I have not included the `RowObjectFilter`, `WeakSet` and other classes as they are specific to Java. You would need to implement these classes or their equivalent in Python for this code to work.