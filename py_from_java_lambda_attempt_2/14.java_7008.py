Here is the translation of the Java code into Python:

```Python
import logging

class DBAnnotatedObjectValidator:
    def __init__(self, ctx, type):
        self.ctx = ctx
        self.type = type
        self.fields_by_name = {}
        self.columns_by_name = {}

    def add_annotated_field(self, field):
        annotation = getattr(field, 'annotation', None)
        assert annotation is not None
        self.fields_by_name[annotation.column] = DBAnnotatedFieldValidator(ctx, field)

    def add_annotated_column(self, column):
        annotation = getattr(column, 'annotation', None)
        assert annotation is not None
        self.columns_by_name[annotation.value] = DBAnnotatedColumnValidator(ctx, column)

    def validate(self):
        if hasattr(self.type, 'annotation') and self.type.annotation.version < 0:
            logging.error(f"@{DBAnnotatedObjectInfo.__name__}.version cannot be negative")
        
        for field_validator in self.fields_by_name.values():
            field_validator.validate()
        
        for column_validator in self.columns_by_name.values():
            column_validator.validate()

    def check_missing(self):
        names = set(list(self.fields_by_name.keys()) + list(self.columns_by_name.keys()))
        for name in names:
            if name not in self.fields_by_name and name in self.columns_by_name:
                logging.error(f"@{DBAnnotatedColumn.__name__} is missing corresponding @{DBAnnotatedField.__name__} of the same column name: {name}")
            
            if name not in self.columns_by_name and name in self.fields_by_name:
                logging.warning(f"@{DBAnnotatedField.__name__} is missing corresponding @{DBAnnotatedColumn.__name__} of the same column name: {name}")

            if name in self.fields_by_name and name in self.columns_by_name:
                check_access(self.fields_by_name[name].field, self.columns_by_name[name].column, name)

    def check_access(self, field, column, name):
        if not AccessSpec.is_same_or_more_permissive(AccessSpec.get(field.modifiers), AccessSpec.get(column.modifiers)):
            logging.warning(f"Field with @{DBAnnotatedColumn.__name__} should have same or greater access than field with corresponding @{DBAnnotatedField.__name__} for column name: {name}")

class DBAnnotatedFieldValidator:
    def __init__(self, ctx, field):
        self.ctx = ctx
        self.field = field

    def validate(self):
        pass  # This method should be implemented based on the requirements of your application.

class DBAnnotatedColumnValidator:
    def __init__(self, ctx, column):
        self.ctx = ctx
        self.column = column

    def validate(self):
        pass  # This method should be implemented based on the requirements of your application.
```

Please note that this translation is not a direct conversion from Java to Python. The logic and structure of the code remain mostly the same, but some parts have been modified or re-written in order to make them more idiomatic for Python.

Also, please replace `logging` with your actual logging mechanism if you are using one.