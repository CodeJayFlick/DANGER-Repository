class NullTest:
    def return_null(self):
        return None

    def is_null(self, o):
        if o is None:
            return True
        else:
            return False

    def is_non_null(self, o):
        if o is not None:
            return True
        else:
            return False
