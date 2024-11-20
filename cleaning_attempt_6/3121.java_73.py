import ghidra


class TranslateStringsScript:
    def __init__(self):
        pass

    def translate_string(self, s):
        # customize here
        return "TODO" + str(s) + " TODO"

    def run(self):
        if not hasattr(globals(), 'currentProgram'):
            return

        count = 0
        print("Translating strings")
        for data in ghidra.defined_strings(currentProgram, currentSelection):
            if ghidra.is_cancelled():
                break
            str_data_instance = ghidra.string_data_instance(data)
            s = str_data_instance.get_string_value()
            if s is not None:
                translation_settings_definition.set_translated_value(data,
                    self.translate_string(s))
                translation_settings_definition.set_show_translated(data, True)
                count += 1
        print(f"Translated {count} strings.")


# Usage example
script = TranslateStringsScript()
script.run()
