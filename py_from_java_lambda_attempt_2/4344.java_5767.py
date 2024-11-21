Here is the translation of the Java code to Python:
```
class ViewStringsContext:
    def __init__(self, provider: 'ViewStringsProvider', strings_table):
        self.provider = provider
        self.strings_table = strings_table

    @property
    def strings_table(self) -> object:
        return self.strings_table

    def get_count(self) -> int:
        return self.provider.get_selected_row_count()

    def get_program(self) -> 'Program':
        return self.provider.get_program()

    def get_data_location_list(self) -> list['ProgramLocation']:
        return self.provider.get_selected_data_locations(None)

    def get_filtered_data_location_list(self, filter: callable) -> list['ProgramLocation']:
        return self.provider.get_selected_data_locations(filter)
```
Note that I've used Python's type hinting system to indicate the types of variables and method parameters. This is not strictly necessary for the code to work, but it can be helpful for documentation and static analysis purposes.

Also, I've assumed that `ViewStringsProvider` is a separate class or module that provides some kind of string-view-related functionality. If you want me to translate that part as well, please let me know!