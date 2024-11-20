import importlib.util
from typing import Optional

class CommandReloader:
    _sync_commands_method: Optional[method] = None

    @classmethod
    def __init__.py(cls):
        try:
            revision = Bukkit.get_server().getClass().getPackage().getName().split('.')[3]
            craft_server_module_name = f"org.bukkit.craftbukkit.{revision}.CraftServer"
            craft_server_module_spec = importlib.util.spec_from_file_location(craft_server_module_name, None)
            craft_server_module = importlib.util.module_from_spec(craft_server_module_spec)

            _sync_commands_method = getattr(craft_server_module, "syncCommands")
        except (importlib.errors.ImportError, AttributeError):
            pass

    @classmethod
    def sync_commands(cls, server: object) -> bool:
        if cls._sync_commands_method is None:
            return False  # Method not available, can't sync

        try:
            result = _sync_commands_method(server)
            return True  # Sync probably succeeded
        except Exception as e:
            if Skript.debug():
                print("Sync commands failed; stack trace for debugging below")
                raise e from None
            return False  # Something went wrong, sync probably failed

if __name__ == "__main__":
    pass
