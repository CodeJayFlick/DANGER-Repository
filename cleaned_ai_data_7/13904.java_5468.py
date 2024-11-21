# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import exceptions

class EmployeeHandle:
    def __init__(self, db):
        self.db = db

    def receive_request(self, *parameters):
        try:
            return self.update_db(*parameters)
        except DatabaseUnavailableException as e:
            raise e

    def update_db(self, *parameters):
        o = parameters[0]
        if not hasattr(o, 'id'):
            raise ValueError("Invalid order object")
        if self.db.get(o.id) is None:
            self.db.add(o)
            return str(o.id)  # true rcvd - change addedToEmployeeHandle to True else don't do anything
        return None

class DatabaseUnavailableException(Exception):
    pass
