class SettingsDefinition:
    @staticmethod
    def concat(settings: list, *additional) -> list:
        if additional == []:
            return settings
        if settings == []:
            return [s for s in additional]
        
        result = settings + list(additional)
        return result

    def has_value(self, setting):
        pass  # Not implemented in Java either!

    @property
    def name(self) -> str:
        raise NotImplementedError("Name not implemented")

    @property
    def description(self) -> str:
        raise NotImplementedError("Description not implemented")

    def clear(self, settings: dict):
        for key in list(settings.keys()):
            if self.name() == key:
                del settings[key]

    def copy_setting(self, src_settings: dict, dest_settings: dict):
        for key, value in src_settings.items():
            if self.name() == key:
                dest_settings[key] = value
