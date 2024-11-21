class FunctionBitPatternsExplorerPlugin:
    def __init__(self):
        self.provider = None
        self.patterns = set()

    # patterns selected by the user

    def add_pattern(self, pattern_row):
        self.patterns.add(pattern_row)

    def remove_patterns(self, patterns_to_remove):
        self.patterns.difference_update(patterns_to_remove)

    def get_patterns(self):
        return self.patterns.copy()

    def clear_patterns(self):
        self.patterns.clear()

    def update_clipboard(self):
        if self.provider:
            self.provider.update_clipboard()

    def highlight_matches(self, matches):
        highlighted = ProgramSelection(matches)
        high_light_event = ProgramHighlightPluginEvent("FunctionBitPatternsExplorerPlugin", highlighted, None)  # getCurrentProgram() not available in Python
        fire_plugin_event(high_light_event)

    def dispose(self):
        if self.provider:
            self.provider.dispose()
