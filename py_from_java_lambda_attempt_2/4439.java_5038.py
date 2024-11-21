Here is the translation of the Java code into Python:

```Python
class GenerateOldLanguagePlugin:
    def __init__(self):
        pass

    @property
    def OLD_ LANG_FILTER(self):
        return ExtensionFileFilter("lang", "Old Language File")

    @property
    def TRANSLATOR_FILTER(self):
        return ExtensionFileFilter("trans", "Simple Translator File")

    def init(self, plugintool):
        self.generate_old_language_action = DockingAction(
            "Generate Old Language File",
            getName()
        )
        self.generate_translator_action = DockingAction(
            "Generate Simple Language Translator",
            getName()
        )

        self.generate_old_language_action.actionPerformed = lambda context: self.generate_old_language(context)
        self.generate_translator_action.actionPerformed = lambda context: self.generate_translator(context)

    def generate_old_language(self, context):
        dialog_provider = GenerateOldLanguageDialog(False)
        tool.show_dialog(dialog_provider)

    def generate_translator(self, context):
        if not hasattr(self, 'old_lang_file'):
            return
        lang = select_lang_panel.get_selected_language()
        if lang is None:
            status_text.set("Please select old language")
            return

        file = chooser.get_selected_file(True)
        if file is None:
            return

        try:
            OldLanguageFactory.create_old_language_file(lang, file)
            close()

            int resp = OptionDialog.show_yes_no_dialog(
                tool.get_tool_frame(),
                "Create Simple Translator?",
                f"Old language file generated successfully.\n\nWould you like to create a simple translator to another language?"
            )
            if resp == OptionDialog.YES_OPTION:
                GenerateTranslatorDialog(translator_dl_provider)
        except LanguageNotFoundException as e:
            raise AssertException(e)

    def close(self):
        super().close()
        select_lang_panel.dispose()

class GenerateOldLanguageDialog(DialogComponentProvider):
    def __init__(self, skip_old_lang_generation):
        super().__init__("Select Old Language", True, True, True, False)
        self.old_lang = None
        self.old_lang_file = None

    @property
    def panel(self):
        if not hasattr(self, '_panel'):
            select_lang_panel = SelectLanguagePanel(DefaultLanguageService.get_language_service())
            _panel = JPanel(FlowLayout())
            _panel.add(select_lang_panel)
            add_work_panel(_panel)

        return self._panel

    def close(self):
        super().close()
        select_lang_panel.dispose()

class GenerateTranslatorDialog(DialogComponentProvider):
    def __init__(self, old_lang, file):
        super().__init__("Select New Language", True, True, True, False)
        self.old_lang = old_lang
        self.file = file

    @property
    def panel(self):
        if not hasattr(self, '_panel'):
            select_lang_panel = SelectLanguagePanel(DefaultLanguageService.get_language_service())
            _panel = JPanel(FlowLayout())
            _panel.add(select_lang_panel)
            add_work_panel(_panel)

        return self._panel

    def close(self):
        super().close()
        select_lang_panel.dispose()

class DummyLanguageTranslator(LanguageTranslatorAdapter):
    def __init__(self, old_language, new_language):
        super().__init__(old_language.get_language_id(), old_language.get_version(),
                         new_language.get_language_id(), new_language.get_version())

    @property
    def can_map_spaces(self):
        return True

    @property
    def can_map_context(self):
        return False

class DeprecatedLanguageService(LanguageService):
    def __init__(self, include_old_languages):
        self.lang_service = DefaultLanguageService.get_language_service()
        self.old_lang_factory = OldLanguageFactory.get_old_language_factory()

    def get_default_language(self, processor):
        raise UnsupportedOperationException()

    # ... other methods ...
```

Note that this is a direct translation of the Java code into Python. Some parts may not be exactly equivalent due to differences in syntax and semantics between the two languages.