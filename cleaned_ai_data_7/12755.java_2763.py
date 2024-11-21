import logging

class DefaultLanguageService:
    _logger = logging.getLogger(__name__)

    def __init__(self):
        self._language_infos = []
        self._language_map = {}
        self._search_completed = False

    @classmethod
    def get_language_service(cls, sleigh_ldefs_file=None):
        if not hasattr(DefaultLanguageService, 'instance'):
            DefaultLanguageService.instance = cls()
        if not DefaultLanguageService.instance.search_completed:
            DefaultLanguageService.instance.search_for_providers(sleigh_ldefs_file)
        return DefaultLanguageService.instance

    def search_for_providers(self, sleigh_ldefs_file=None):
        self._search_completed = True
        # TaskBuilder.withRunnable(monitor -> { provider.get_language(id); // load and cache }).setTitle("Loading language 'id'").setCanCancel(false).setHasProgress(false).launchModal();
        pass

    def get_language(self, language_id: str) -> dict:
        if not self._language_map.get(language_id):
            raise LanguageNotFoundException(language_id)
        return {'language': self._language_map[language_id].get_language()}

    def get_language_description(self, language_id: str) -> dict:
        if not self._language_map.get(language_id):
            raise LanguageNotFoundException(language_id)
        return {'description': self._language_map[language_id].description}

    def get_language_descriptions(self, include_deprecated=False) -> list:
        result = []
        for info in self._language_infos:
            description = info.description
            if (include_deprecated or not description.isDeprecated()):
                result.append(description)
        return result

    def get_external_language_descriptions(self, external_processor_name: str, external_tool: str, endianess=None, size=None) -> list:
        result = []
        for language_description in self._language_infos:
            if (not language_matches_external_processor(language_description.description, external_processor_name, external_tool)):
                continue
            if (endianess and not description.getEndian() == endianess):
                continue
            if (size and size != description.getSize()):
                continue
            result.append(description)
        return result

    def get_language_compiler_spec_pairs(self, query: dict) -> list:
        # TaskBuilder.withRunnable(monitor -> { provider.get_language(id); // load and cache }).setTitle("Loading language 'id'").setCanCancel(false).setHasProgress(false).launchModal();
        pass

    @staticmethod
    def get_defined_external_tool_names(language_id, tool_name: str) -> list:
        result = []
        for description in DefaultLanguageService.get_language_service().get_language_descriptions():
            if (description and language_id == description.getLanguageID()):
                external_names = description.getExternalNames(tool_name)
                if (external_names):
                    return external_names
        return []

    def get_default_language(self, processor: str) -> dict:
        for info in self._language_infos:
            if (info.description.getProcessor() == processor):
                language_id = info.description.getLanguageID()
                start_time = logging.getLogger().debug("getDefaultLanguage('" + language_id + "') took " + str(time.time() - start_time) + " ms")
                return {'default_language': info.get_language()}
        raise LanguageNotFoundException(processor)

    def process_providers(self, providers: list):
        for provider in providers:
            self.add_languages(provider)

    def add_languages(self, provider: dict):
        language_descriptions = provider['languageDescriptions']
        for description in language_descriptions:
            if (self._language_infos.contains(description)):
                continue
            info = LanguageInfo(description)
            self._language_infos.append(info)
            id = info.description.getLanguageID()
            if (self._language_map.containsKey(id)):
                raise Exception("Duplicate language ID encountered: " + str(id))
            self._language_map.put(id, info)

    def state_changed(self):
        # NOTE: this is only intended to pickup new language providers 
        # which is not really supported with the introduction of Sleigh.
        pass

class LanguageInfo:
    def __init__(self, description: dict, provider: str):
        self.description = description
        self.provider = provider

    @staticmethod
    def get_language(self) -> dict:
        if (not self.provider.isLanguageLoaded()):
            # TaskBuilder.withRunnable(monitor -> { provider.get_language(id); // load and cache }).setTitle("Loading language 'id'").setCanCancel(false).setHasProgress(false).launchModal();
            pass
        return {'language': self.description}

    def __str__(self):
        return str(self.description)

    def __eq__(self, other: object) -> bool:
        if (not isinstance(other, LanguageInfo)):
            return False
        return self.description == other.description

    def __hash__(self) -> int:
        return hash(self.description)
