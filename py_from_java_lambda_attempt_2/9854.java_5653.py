Here is the translation of the Java code to Python:

```Python
class TableTextFilter:
    def __init__(self, text_filter: 'TextFilter', transformer):
        self.text_filter = text_filter
        self.transformer = transformer

    def is_sub_filter_of(self, table_filter):
        if not isinstance(table_filter, type(self)):
            return False
        
        other = table_filter
        if not self.text_filter.is_sub_filter_of(other.text_filter):
            return False
        
        return type(self.transformer) == type(other.transformer)

    def accepts_row(self, row_object):
        transform = self.transformer.transform(row_object)
        for string in transform:
            if self.text_filter.matches(string):
                return True
        return False

    def __hash__(self):
        raise NotImplementedError()

    def __eq__(self, other):
        if self is other:
            return True
        
        if other is None or type(self) != type(other):
            return False
        
        other = TableTextFilter(*other)
        
        return (self.text_filter == other.text_filter and
                self.transformer == other.transformer)

    def __str__(self):
        return f"{type(self).__name__} - filter='{self.text_filter.get_filter_text()}'"
```

Note that Python does not have a direct equivalent to Java's generics, so I've omitted the type parameter `<ROW_OBJECT>` from the class definition. Also, some methods like `hashCode()` and `equals()` are implemented differently in Python due to its dynamic typing nature.