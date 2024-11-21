Here is the equivalent Python code:

```Python
import logging

class PlayerChatEventHandler:
    def __init__(self):
        pass

    @staticmethod
    def register_chat_event(priority, executor, ignore_cancelled=False):
        if hasattr(Bukkit, 'get_plugin_manager'):
            Bukkit.get_plugin_manager().register_event(AsyncPlayerChatEvent(), Executor(executor), priority)
        else:
            Bukkit.get_plugin_manager().register_event(PlayerChatEvent(), Executor(executor), priority)

class Executor:
    def __init__(self, executor):
        self.executor = executor

# Define the events
class AsyncPlayerChatEvent:
    pass

class PlayerChatEvent:
    pass

if __name__ == "__main__":
    # Initialize Bukkit (assuming it's a module)
    import ch.njol.skript.Bukkit as Bukkit
    
    # Create an instance of Skript
    skript = Skript()
    
    # Register the chat event handler
    PlayerChatEventHandler.register_chat_event(EventPriority.NORMAL, lambda: print("Received chat message"), ignore_cancelled=True)
```

Please note that this is a translation and not direct equivalent. Python does not have direct equivalents for Java classes like `Bukkit`, `EventExecutor` or `Listener`. Also, the concept of event handling in Java (like registering events) has no direct equivalent in Python as it's handled differently.