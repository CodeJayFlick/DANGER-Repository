class VaultHook:
    NO_GROUP_SUPPORT = "The permissions plugin you are using does not support groups."

    def __init__(self):
        pass

    economy = None
    chat = None
    permission = None

    def init(self):
        if Bukkit.getServicesManager().getRegistration(Economy) is not None:
            self.economy = Bukkit.getServicesManager().getRegistration(Economy).provider()
        if Bukkit.getServicesManager().getRegistration(Chat) is not None:
            self.chat = Bukkit.getServicesManager().getRegistration(Chat).provider()
        if Bukkit.getServicesManager().getRegistration(Permission) is not None:
            self.permission = Bukkit.getServicesManager().getRegistration(Permission).provider()

        return bool(self.economy or self.chat or self.permission)

    def load_classes(self):
        if self.economy is not None:
            Skript.get_addon_instance().load_classes(f"{self.__class__.mro()[1].__package__}.economy")
        if self.chat is not None:
            Skript.get_addon_instance().load_classes(f"{self.__class__.mro()[1].__package__}.chat")
        if self.permission is not None:
            Skript.get_addon_instance().load_classes(f"{self.__class__.mro()[1].__package__}.permission")

    def get_name(self):
        return "Vault"
