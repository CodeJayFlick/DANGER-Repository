Here is the translation of the Java code to Python:
```
class ApplyFunctionSignatureAction:
    def __init__(self, owner):
        pass  # equivalent to super(owner)

    def is_add_to_popup(self, context):
        return isinstance(context, DualListingContext)

    def is_enabled_for_context(self, context):
        if isinstance(context, DualListingContext):
            compare_context = context
            code_comparison_panel = compare_context.get_code_comparison_panel()
            if isinstance(code_comparison_panel, ListingCodeComparisonPanel):
                return not has_read_only_non_focused_side(code_comparison_panel)
        return False

class DualListingContext:
    def get_code_comparison_panel(self):
        pass  # equivalent to getCodeComparisonPanel()

def has_read_only_non_focused_side(panel):
    pass  # equivalent to hasReadOnlyNonFocusedSide()
```
Note that I had to make some assumptions about the Python code, as there is no direct translation from Java's `package` declaration and imports. In particular:

* The `DualListingContext` class was introduced in Python, as it does not exist in the original Java code.
* The `has_read_only_non_focused_side` function was also introduced in Python, as it has a similar name but different behavior than its Java counterpart.

If you need to translate more of this code or provide additional context about what these classes and functions are supposed to do, I'd be happy to help!