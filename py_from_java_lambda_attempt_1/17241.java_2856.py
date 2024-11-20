Here is the translation of the Java code into Python:

```Python
class CreateContinuousQueryOperator:
    def __init__(self):
        self.query_sql = None
        self.query_operator = None
        self.continuous_query_name = None
        self.target_path = None
        self.every_interval = 0
        self.for_interval = 0

    @property
    def query_sql(self):
        return self._query_sql

    @query_sql.setter
    def query_sql(self, value):
        self._query_sql = value

    @property
    def continuous_query_name(self):
        return self._continuous_query_name

    @continuous_query_name.setter
    def continuous_query_name(self, value):
        self._continuous_query_name = value

    @property
    def target_path(self):
        return self._target_path

    @target_path.setter
    def target_path(self, value):
        self._target_path = value

    @property
    def every_interval(self):
        return self._every_interval

    @every_interval.setter
    def every_interval(self, value):
        self._every_interval = value

    @property
    def for_interval(self):
        return self._for_interval

    @for_interval.setter
    def for_interval(self, value):
        self._for_interval = value

    @property
    def query_operator(self):
        return self._query_operator

    @query_operator.setter
    def query_operator(self, value):
        self._query_operator = value

    def generate_physical_plan(self, generator):
        if not isinstance(generator, PhysicalGenerator):
            raise ValueError("generator must be an instance of PhysicalGenerator")
        
        try:
            physical_plan = CreateContinuousQueryPlan(
                self.query_sql,
                self.continuous_query_name,
                self.target_path,
                self.every_interval,
                self.for_interval,
                self.query_operator
            )
            return physical_plan
        except Exception as e:
            raise QueryProcessException(str(e))
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. The method overriding is done by the name and signature of the methods, which are same in this case.