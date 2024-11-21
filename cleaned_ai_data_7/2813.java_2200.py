class DBObjectColumn:
    instances = []

    @classmethod
    def get(cls, column_number):
        while len(cls.instances) <= column_number:
            cls.instances.append(None)
        column = cls.instances[column_number]
        if column is None:
            column = cls(column_number)
            cls.instances[column_number] = column
        return column

    def __init__(self, column_number):
        self.columnNumber = column_number


# Example usage:

DBObjectColumn.get(0)  # This will create the first instance of DBObjectColumn if it doesn't exist already.
DBObjectColumn.get(1)
...
