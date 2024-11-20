Here is the translation of the given Java code into Python:

```Python
class BookmarkComparator:
    def compare(self, bm1: 'Bookmark', bm2: 'Bookmark') -> int:
        bt1 = bm1.type_string()
        bt2 = bm2.type_string()
        bc1 = bm1.category()
        bc2 = bm2.category()

        type_compare = bt1.casefold().compare(bt2.casefold())
        
        if type_compare == 0:
            return bc1.casefold().compare(bc2.casefold())

        return type_compare

class Bookmark:
    def __init__(self):
        pass
    
    def get_category(self) -> str:
        # Implement your logic here
        pass

    def get_type_string(self) -> str:
        # Implement your logic here
        pass
```

Note that the `Bookmark` class is not fully implemented in this translation, as it was not provided in the original Java code. You would need to implement the methods `get_category()` and `get_type_string()` according to your specific requirements.