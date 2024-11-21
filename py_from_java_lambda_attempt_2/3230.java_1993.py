Here is the translation of the given Java code into Python:

```Python
class MoveBlockListener:
    def state_changed(self):
        """Notification that something has changed."""
        pass
    
    def move_block_completed(self, cmd):
        """
        Notification that the move block completed.
        
        :param cmd: The command that was executed to move the block; 
                    the command has the status of whether the block was moved successfully
        """
        pass

# Example usage:
class MyMoveBlockListener(MoveBlockListener):
    def state_changed(self):
        print("State changed!")
    
    def move_block_completed(self, cmd):
        if cmd.status:  # Assuming 'status' is a boolean attribute in the command object
            print(f"Move block completed successfully with {cmd}")
        else:
            print(f"Failed to move block. Reason: {cmd}")

my_listener = MyMoveBlockListener()
```

Note that Python does not have direct equivalents for Java's `interface` and `public`, so we define a class instead, which can be used as an interface in the sense that it defines methods without providing any implementation.