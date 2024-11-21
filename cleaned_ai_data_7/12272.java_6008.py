class DataTypeConflictException(Exception):
    def __init__(self, dt1=None, dt2=None, message=""):
        super().__init__(message)
        self.datatype1 = dt1
        self.datatype2 = dt2

def get_conflicting_data_types(self):
    return [self.datatype1, self.datatype2]
