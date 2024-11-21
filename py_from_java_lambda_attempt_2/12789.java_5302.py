Here is the translation of the Java code into Python:

```Python
class LanguageTranslatorFactory:
    LANGUAGE_TRANSLATOR_FILE_EXT = ".trans"
    
    def __init__(self):
        self.translator_map = {}
        self.translator_version_map = {}
        self.bad_file_count = 0
    
    @staticmethod
    def get_language_translator_factory():
        if not hasattr(LanguageTranslatorFactory, 'instance'):
            LanguageTranslatorFactory.instance = LanguageTranslatorFactory()
        return LanguageTranslatorFactory.instance

    def add_translator(self, translator):
        if translator.get_old_language_id() == translator.get_new_language_id():
            if translator.get_old_version() + 1 != translator.get_new_version():
                print("Language version translator to_ version same as from_ version+1:", translator)
            self.add_to_map(translator_version_map, translator, True)
        else:
            self.add_to_map(translator_map, translator, False)

    def process_minion(self, minion):
        for translator in minion.get_language_translators():
            self.add_translator(translator)

    @staticmethod
    def get_simple_translators(list_):
        files = Application.find_files_by_extension_in_application(LANGUAGE_TRANSLATOR_FILE_EXT)
        for file in files:
            try:
                list_.append(SimpleLanguageTranslator.get_simple_language_translator(file))
            except Exception as e:
                print("Failed to parse:", file, str(e))
                LanguageTranslatorFactory.instance.bad_file_count += 1

    @staticmethod
    def get_explicit_translators(list_):
        for translator_class in ClassSearcher.get_classes(LanguageTranslator):
            if not Modifier.is_public(translator_class.getModifiers()) or Modifier.is_static(
                    translator_class.getModifiers()) or Modifier.is_abstract(
                translator_class.getModifiers()):
                continue

            try:
                list_.append((LanguageTranslator)(translator_class.__new__()))
            except Exception as e:
                print("Failed to instantiate language translator:", str(e))
                LanguageTranslatorFactory.instance.bad_file_count += 1

    def validate_all_translators(self):
        error_count = 0
        for translators in self.translator_map.values():
            for translator in translators:
                if not translator.is_valid():
                    error_count += 1
        for translators in self.translator_version_map.values():
            for translator in translators:
                if not translator.is_valid():
                    error_count += 1
        return error_count

    def get_all_translators(self):
        list_ = []
        for translators in self.translator_map.values():
            list_.extend(translators)
        for translators in self.translator_version_map.values():
            list_.extend(translators)
        return list_

    @staticmethod
    def expand_translator(translator, from_version):
        if translator.get_old_version() != from_version:
            expanded_from_translator = LanguageTranslatorFactory.get_language_version_translator(
                translator.get_old_language_id(), from_version, translator.get_old_version())
            if expanded_from_translator is None:
                return None
            translator = FactoryLanguageTranslator(expanded_from_translator, translator)

        if translator.get_new_version() != to_version:
            next_translator = LanguageTranslatorFactory.get_next_translator(
                self.translator_version_map[translator.get_new_language_id()], to_version)
            if next_translator is None or next_translator.get_old_version() > to_version:
                return None
            if from_version != next_translator.get_old_version():
                gap_translator = LanguageTranslatorAdapter.getDefault_language_translator(
                    translator.get_new_language_id(), from_version, next_translator.get_old_version())
                if gap_translator is None:
                    return None
                translator = FactoryLanguageTranslator(gap_translator, translator)
            else:
                translator = new_factory_language_translator(translator, next_translator)

        return translator

    @staticmethod
    def get_next_translator(version_translators, version):
        index = bisect.bisect_left(version_translators, (version,))
        if index < len(version_translators) and version_translators[index].get_old_version() == version:
            return version_translators[index]
        else:
            return None

    def get_language_translator(self, from_language, to_language):
        if isinstance(to_language, OldLanguage):
            raise Exception("toLanguage instanceof OldLanguage")

        if from_language.get_language_id().equals(to_language.get_language_id()):
            # Handle version change
            if from_language.get_version() >= to_language.get_version():
                return None

            return self.get_language_version_translator(from_language.get_language_id(), 
                    from_language.get_version(), to_language.get_version())

        list_ = self.translator_map[from_language.get_language_id()]
        for translator in list_:
            if translator.get_old_version() < from_language.get_version() or not to_language.get_language_id().equals(translator.get_new_language_id()):
                continue
            return self.expand_translator(translator, from_language.get_version())

        return LanguageTranslatorAdapter.getDefault_language_translator(from_language, 
                to_language)

    def get_language_version_translator(self, language_id, from_version, to_version):
        list_ = self.translator_version_map[language_id]
        if not list_:
            return None

        translator = None
        for i in range(len(list_) - 1, -1, -1):
            next_translator = list_[i]
            if next_translator.get_old_version() > to_version or next_translator.get_new_version() < from_version:
                break
            elif next_translator.get_old_version() == from_version and i != len(list_)-1:
                gap_translator = LanguageTranslatorAdapter.getDefault_language_translator(
                    language_id, from_version, list_[i+1].get_old_version())
                if gap_translator is None:
                    return None
                translator = FactoryLanguageTranslator(gap_translator, next_translator)
            else:
                translator = next_translator

        return translator


class LanguageTranslatorAdapter:

    @staticmethod
    def get_default_language_translator(language_id, from_version, to_version):
        # implementation specific
        pass


class SimpleLanguageTranslator:

    @staticmethod
    def get_simple_language_translator(file):
        try:
            # implementation specific
            pass
        except Exception as e:
            print("Failed to parse:", file, str(e))
            return None

    @staticmethod
    def get_next_translators(list_):
        for i in range(len(list_) - 1, -1, -1):
            if list_[i].get_old_version() > from_version or list_[i+1].get_new_version() < to_version:
                break
            elif list_[i].get_old_version() == from_version and i != len(list_)-1:
                gap_translator = LanguageTranslatorAdapter.getDefault_language_translator(
                    language_id, from_version, list_[i+1].get_old_version())
                if gap_translator is None:
                    return None
                translator = FactoryLanguageTranslator(gap_translator, next_translator)
            else:
                translator = next_translator

        return translator


class LanguageTranslator:

    def get_new_language(self):
        pass

    def get_old_language(self):
        pass

    def get_old_register(self, old_addr, size):
        pass

    def get_old_register_containing(self, old_addr):
        pass

    def get_old_context_register(self):
        pass

    def get_new_context_register(self):
        pass

    def get_new_register(self, old_reg):
        pass

    def is_value_translation_required(self, reg):
        pass

    def get_new_register_value(self, reg_value):
        pass

    def fixup_instructions(self, program, language, monitor):
        pass


class FactoryLanguageTranslator(LanguageTranslator):

    def __init__(self, t1, t2):
        self.t1 = t1
        self.t2 = t2

    @staticmethod
    def get_next_translator(list_, version):
        index = bisect.bisect_left(list_, (version,))
        if index < len(list_) and list_[index].get_old_version() == version:
            return list_[index]
        else:
            return None


class TemporaryCompilerSpec:

    @staticmethod
    def get_compiler_spec_id(self, old_compiler_spec_id):
        pass

    @staticmethod
    def fixup_instructions(self, program, language, monitor):
        pass