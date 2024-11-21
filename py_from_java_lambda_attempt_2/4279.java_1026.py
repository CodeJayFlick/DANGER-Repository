Here is a translation of the Java code into Python:

```Python
class ListingDisplaySearcher:
    def __init__(self, tool, program, start_location, search_addresses, options):
        self.tool = tool
        self.program = program
        self.start_location = start_location
        self.search_addresses = search_addresses
        self.options = options

        if not is_initialized:
            initialize_start_address(search_addresses)
            initialize_address_set()

    def next(self):
        if location_list.size() == 0:
            find_next()
        return current_location

    def hasNext(self):
        if location_list.size() == 0:
            find_next()
        return options.is_forward() and location_iterator.has_next() or not options.is_forward() and location_iterator.has_previous()

    # ... other methods ...

class MnemonicText:
    def __init__(self, mnemonic, operands):
        self.mnemonic = mnemonic
        self.text = f"{mnemonic} {operands}"

    def get_mnemonic_length(self):
        return len(mnemonic)

    def get_text(self):
        return text

# Inner classes ...
```

Please note that Python does not have direct equivalent of Java's `class` keyword. In Python, we define a class using the `class` statement followed by the name of the class and parentheses containing its base classes.

Also, Python is dynamically typed language which means you don't need to declare variable types before using them.