class VTListingContext:
    def __init__(self, provider: object, navigatable: object):
        super().__init__(provider, navigatable)

    def set_code_comparison_panel(self, code_comparison_panel: 'CodeComparisonPanel'):
        self.code_comparison_panel = code_comparison_panel

    def get_code_comparison_panel(self) -> 'CodeComparisonPanel':
        return self.code_comparison_panel


class CodeComparisonPanel:
    pass
