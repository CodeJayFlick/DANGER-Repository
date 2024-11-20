Here is the translation of the Java code into Python:

```Python
class DialogFilterRow:
    def __init__(self, dialog_model, logic_operation):
        self.dialog_model = dialog_model
        self.logic_operation = logic_operation
        self.column_condition_set = None
        do_set_column_data(dialog_model.get_all_column_filter_data()[0])

    @staticmethod
    def do_set_column_data(column_data):
        if column_data is not None:
            self.column_condition_set = DialogFilterConditionSet(self, column_data)

    def set_column_data(self, column_data):
        self.do_set_column_data(column_data)
        self.dialog_model.filter_row_changed(self)

    def get_logic_operation(self):
        return self.logic_operation

    @staticmethod
    def get_all_column_data(dialog_model):
        return dialog_model.get_all_column_filter_data()

    def get_column_filter_data(self):
        if self.column_condition_set is not None:
            return self.column_condition_set.get_column_filter_data()
        else:
            return None

    def has_valid_filter_value(self):
        if self.column_condition_set is not None:
            return self.column_condition_set.has_valid_filter_value()
        else:
            return False

    def get_filter_conditions(self):
        if self.column_condition_set is not None:
            return list(self.column_condition_set.get_filter_conditions())
        else:
            return []

    def add_filter_condition(self):
        if self.column_condition_set is not None:
            return self.column_condition_set.add_filter_condition()
        else:
            return None

    def add_to_table_filter(self, table_column_filter):
        if self.column_condition_set is not None and table_column_filter is not None:
            self.column_condition_set.add_to_table_filter(table_column_filter, self.logic_operation)

    @property
    def data_source(self):
        return self.dialog_model.get_data_source()

    def editor_value_changed(self, editor):
        self.dialog_model.editor_value_changed(editor)

    def condition_set_changed(self, condition_set):
        if condition_set is not None:
            self.dialog_model.filter_row_changed(self)
        else:
            pass

    @property
    def table_model(self):
        return self.dialog_model.get_table_model()

    def delete(self):
        self.dialog_model.delete_filter_row(self)

    def __str__(self):
        return f"{{\n\toperation: {self.logic_operation},\n\tconditions: {self.column_condition_set}\n}}"
```

Please note that Python does not support operator overloading like Java, so I have removed the `@Override` annotation and replaced it with a simple string representation of the object.