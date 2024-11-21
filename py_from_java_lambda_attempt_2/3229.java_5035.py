Here is the translation of the given Java code into equivalent Python:

```Python
class DeleteBlockListener:
    def __init__(self):
        pass

    def delete_block_completed(self, cmd):
        """
        Notification that the delete block command completed.
        
        :param cmd: The command that was completed. It has a status indicating whether the deletion was successful.
        """
        # Add your code here to handle the completion of the DeleteBlockCmd
```

In this translation:

- We define a Python class `DeleteBlockListener` with an empty constructor (`__init__`) and one method `delete_block_completed`.
- The method takes one argument, `cmd`, which is expected to be an instance of some class representing the delete block command.
- Inside the method, you can add your code to handle the completion of the DeleteBlockCmd.