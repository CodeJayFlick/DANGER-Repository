class RequiresTarget:
    def __init__(self):
        pass

    def obtain_target(self) -> object:
        """
        Perform whatever minimal setup is necessary to obtain a target suitable for testing
        
        For user-mode debugging this is almost certainly a TargetProcess.
        
        @return the target
        @throws Exception if anything goes wrong
        """
        # Add your code here to implement the logic of obtaining_target method
        pass

    def __str__(self):
        return "RequiresTarget"
