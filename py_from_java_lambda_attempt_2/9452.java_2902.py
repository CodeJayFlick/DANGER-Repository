Here is the translation of the given Java code into Python:

```Python
import collections

class OptionsTreeNode:
    OPEN_Folder_ICON = None
    CLOSED_FOLDER_ICON = None
    PROPERTIES_ICON = None

    def __init__(self, name, options):
        self.name = name
        self.options = options

    @staticmethod
    def get_last_name_in_prefix(prefix_string):
        # assume the delimiter is on the end of the string--chop it off!
        length = len(prefix_string)
        substring = prefix_string[:length-1]

        # find the last delimiter in the remaining prefix, as we want the name after that
        last_delimiter_index = substring.rfind('.')

        if last_delimiter_index < 0:
            return substring

        # the name is all text from the last delimiter
        length = len(substring)
        return substring[last_delimiter_index+1:length]

    def generate_children(self):
        child_list = []
        if self.options.get_options_editor() == None:  # if hasOptionsEditor, don't show child options
            child_options_list = self.options.get_child_options()
            for child_options in child_options_list:
                child_list.append(OptionsTreeNode(child_options))
        return sorted(child_list)

    def is_leaf(self):
        return len(self.generate_children()) == 0

    def get_icon(self, is_expanded):
        if self.is_leaf():
            return self.PROPERTIES_ICON
        else:
            return self.OPEN_Folder_ICON if is_expanded else self.CLOSED_FOLDER_ICON

    def __eq__(self, other):
        if isinstance(other, OptionsTreeNode) and self.name == other.name:
            return True
        return False

    def get_options(self):
        return self.options

    def get_option_names(self):
        if self.options is None:
            return []
        else:
            return self.options.get_leaf_option_names()

    def __str__(self):
        return self.name

    def to_string(self):
        return str(self)

    def compare_to(self, other):
        if isinstance(other, OptionsTreeNode) and self.name == other.name:
            return 0
        elif self.name < other.name:
            return -1
        else:
            return 1

# Example usage:
class Options:
    def __init__(self, name):
        self.name = name
        self.get_child_options()  # This method should be implemented in the actual class.

    def get_leaf_option_names(self):
        pass  # This method should be implemented in the actual class.
```

Please note that Python does not have direct equivalent of Java's `Icon` and `GTreeLazyNode`. The above code uses Python's built-in string representation for icons. Also, some methods like `compareTo(GTreeNode other)` are removed as they do not seem to serve any purpose in this context.