class SimpleWizard:
    def __init__(self):
        self.tobacco = OldTobyTobacco()

    def smoke(self):
        self.tobacco.smoke(self)


class OldTobyTobacco:
    def smoke(self, wizard):
        pass  # implement the logic here


# Usage
wizard = SimpleWizard()
wizard.smoke()
