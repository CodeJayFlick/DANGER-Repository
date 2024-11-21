class OldLanguageMappingService:
    def __init__(self):
        pass

    @staticmethod
    def lookup_magic_string(magic_string, language_replacement_ok):
        factory = PluggableServiceRegistry.get_pluggable_service(OldLanguageMappingService)
        return factory.do_lookup_magic_string(magic_string, language_replacement_ok)

    def do_lookup_magic_string(self, magic_string, language_replacement_ok):
        return None

    @staticmethod
    def validate_pair(pair):
        try:
            lang = DefaultLanguageService.get_language_service().get_language(pair.language_id)
            compiler_spec = lang.get_default_compiler_spec()
            if compiler_spec is not None:
                return pair
            else:
                Msg.warn(OldLanguageMappingService, f"Compiler spec not found: {pair.language_id} -> {pair.compiler_spec_id}")
        except CompilerSpecNotFoundException as e:
            Msg.warn(OldLanguageMappingService, f"Compiler spec not found: {pair.language_id} -> {pair.compiler_spec_id}")

    @staticmethod
    def process_xml_language_string(language_string):
        if language_string is None:
            return None

        index = language_string.rfind(':')
        if index > 0:
            pair = LanguageCompilerSpecPair(LanguageID(language_string[:index]), CompilerSpecID(language_string[index + 1:]))
            return OldLanguageMappingService.validate_pair(pair)
        else:
            return OldLanguageMappingService.lookup_magic_string(language_string, True)


class PluggableServiceRegistry:
    @staticmethod
    def get_pluggable_service(cls):
        pass


class DefaultLanguageService:
    @staticmethod
    def get_language_service():
        pass

    @staticmethod
    def get_language(lang_id):
        pass

    @staticmethod
    def get_default_compiler_spec(self, lang):
        pass


class CompilerSpecNotFoundException(Exception):
    pass


class LanguageCompilerSpecPair:
    def __init__(self, language_id, compiler_spec_id):
        self.language_id = language_id
        self.compiler_spec_id = compiler_spec_id


class CompilerSpecID:
    def __init__(self, id):
        self.id = id


class LanguageID:
    def __init__(self, id):
        self.id = id

