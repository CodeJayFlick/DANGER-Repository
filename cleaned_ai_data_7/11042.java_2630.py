class CheckoutInfo:
    def __init__(self, file):
        self.file = file
        try:
            self.status = file.get_checkout_status()
        except Exception as e:
            raise IOException(f"Error getting checkout status: {e}")

    @property
    def file(self):
        return self.file

    @file.setter
    def file(self, value):
        self.file = value

    @property
    def status(self):
        return self.status

    @status.setter
    def status(self, value):
        self.status = value
