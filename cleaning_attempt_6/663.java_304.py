from typing import TypeVar, Generic

T = TypeVar('T')

class DbgCommand(Generic[T]):
    def valid_in_state(self, state: object) -> bool:
        """Check if this command can be executed given Dbg's current state"""
        pass  # Implement me!

    def invoke(self):
        """Invoke the command"""
        pass  # Implement me!

    def handle_event(self, event: object, pending_command: 'DbgCommand') -> bool:
        """Handle an event that occurred during the execution of this command"""
        return False  # Default implementation

    def complete(self, pending_command: 'DbgCommand') -> T:
        """Called when the manager believes this command is finished executing"""
        pass  # Implement me!
