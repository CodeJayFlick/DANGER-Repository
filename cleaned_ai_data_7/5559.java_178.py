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
