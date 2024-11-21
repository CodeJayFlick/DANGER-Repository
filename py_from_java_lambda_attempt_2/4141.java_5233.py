Here is a translation of the provided Java code into equivalent Python:

```Python
class SetLanguageDialog:
    def __init__(self, tool, program):
        self.select_lang_panel = None
        self.lang_service = DefaultLanguageService()
        self.tool = tool
        self.curr_program = program
        
        lcs_pair = LanguageCompilerSpecPair(program.get_language_id(), 
                                             program.get_compiler_spec().get_compiler_spec_id())
        
        self.select_lang_panel = NewLanguagePanel(lcs_pair)
        self.select_lang_panel.add_selection_listener(self.listener)

    def listener(self, e):
        lang_id = None
        compiler_spec_id = None
        
        if e.selection is not None:
            lang_id = e.selection.get_language_id()
            compiler_spec_id = e.selection.get_compiler_spec_id()

        if (lang_id and self.curr_program.get_language_id() == lang_id) or \
           (compiler_spec_id and 
            self.curr_program.get_compiler_spec().get_compiler_spec_id() == compiler_spec_id):
            #self.select_lang_panel.set_notification_text("Please select a different Language or Compiler Spec.")
            self.status_text = "Please select a different Language or Compiler Spec."
            self.ok_enabled = False
        else:
            #self.select_lang_panel.set_notification_text(None)
            self.status_text = None
            self.ok_enabled = True

    def get_language_description_id(self):
        return self.dialog_language_desc_id

    def get_compiler_spec_description_id(self):
        return self.dialog_compiler_spec_desc_id

    def ok_callback(self):
        selected_lcs_pair = self.select_lang_panel.get_selected_lcs_pair()
        
        if selected_lcs_pair is None:
            self.dialog_language_desc_id = None
            self.dialog_compiler_spec_desc_id = None
        else:
            self.dialog_language_desc_id = selected_lcs_pair.language_id
            self.dialog_compiler_spec_desc_id = selected_lcs_pair.compiler_spec_id
        
        self.close()

    def close(self):
        pass

class DefaultLanguageService:
    @staticmethod
    def get_language_service():
        return None  # Replace with actual implementation.

class LanguageCompilerSpecPair:
    def __init__(self, language_id, compiler_spec_id):
        self.language_id = language_id
        self.compiler_spec_id = compiler_spec_id

# Usage example:

tool = PluginTool()
program = Program()  # Assuming this is a valid program object.
dialog = SetLanguageDialog(tool, program)
```

Please note that the translation was done to provide equivalent Python code. However, some parts of the original Java code may not have direct equivalents in Python due to differences between languages and their respective libraries.