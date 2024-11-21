class CreateContinuousQueryPlan:
    def __init__(self):
        self.query_sql = None
        self.continuous_query_name = None
        self.target_path = None
        self.every_interval = 0
        self.for_interval = 0
        self.query_operator = None
        self.creation_timestamp = 0

    def set_query_sql(self, query_sql):
        self.query_sql = query_sql

    def get_query_sql(self):
        return self.query_sql

    def set_continuous_query_name(self, continuous_query_name):
        self.continuous_query_name = continuous_query_name

    def get_continuous_query_name(self):
        return self.continuous_query_name

    def set_target_path(self, target_path):
        self.target_path = target_path

    def get_target_path(self):
        return self.target_path

    def set_every_interval(self, every_interval):
        self.every_interval = every_interval

    def get_every_interval(self):
        return self.every_interval

    def set_for_interval(self, for_interval):
        self.for_interval = for_interval

    def get_for_interval(self):
        return self.for_interval

    def set_query_operator(self, query_operator):
        self.query_operator = query_operator

    def get_query_operator(self):
        return self.query_operator

    def set_creation_timestamp(self, creation_timestamp):
        self.creation_timestamp = creation_timestamp

    def get_creation_timestamp(self):
        return self.creation_timestamp


class PhysicalPlan:
    pass
