class DeleteBlockListener:
    def __init__(self):
        pass

    def delete_block_completed(self, cmd):
        """
        Notification that the delete block command completed.
        
        :param cmd: The command that was completed. It has a status indicating whether the deletion was successful.
        """
        # Add your code here to handle the completion of the DeleteBlockCmd
