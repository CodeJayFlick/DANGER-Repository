import logging

class ArgsMessage:
    def __init__(self, key):
        self.key = key

    def __str__(self):
        raise NotImplementedError("Not implemented")

    def __str__(self, *args):
        try:
            value = self.get_value()
            if value is None:
                return str(self.key)
            else:
                return f"{value}".format(*args)
        except Exception as e:
            logging.error(f"The formatted message '{self.key}' uses an illegal format: {e}")
            print("[Skript] " + str(e))
            raise

    def get_value(self):
        # This method is not implemented in the original Java code
        pass
