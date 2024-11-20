class HasTranslationValueColumnConstraint:
    def accepts(self, value: str, context: dict) -> bool:
        return value.get_translated_value() is not None and len(value.get_translated_value()) > 0

    def get_name(self) -> str:
        return "Has Translated Value"

    def get_editor(self, column_data_source: list) -> object:
        from ghidra.app.plugin.core.strings import DoNothingColumnConstraintEditor
        return DoNothingColumnConstraintEditor(self)
