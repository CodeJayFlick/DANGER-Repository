class UDTFExecutor:
    def __init__(self, expression):
        self.expression = expression
        self.configurations = UDTFConfigurations()

    def before_start(self, query_id, collector_memory_budget_in_mb, expression_data_type_map):
        try:
            udtf = UDFRegistrationService().reflect(expression)
            parameters = UDFParameters(expression, expression_data_type_map)
            udtf.validate(parameters)
            udtf.before_start(parameters, self.configurations)
            self.configurations.check()
            collector = ElasticSerializableTVList(self.configurations.get_output_data_type(), query_id, collector_memory_budget_in_mb, 1)
        except Exception as e:
            onError("validate(UDFParameterValidator)", str(e))

    def execute(self, row):
        try:
            udtf.transform(row, self.collector)
        except Exception as e:
            onError("transform(Row, PointCollector)", str(e))

    def execute_window(self, row_window):
        try:
            udtf.transform(row_window, self.collector)
        except Exception as e:
            onError("transform(RowWindow, PointCollector)", str(e))

    def terminate(self):
        try:
            udtf.terminate(self.collector)
        except Exception as e:
            onError("terminate(PointCollector)", str(e))

    def before_destroy(self):
        udtf.before_destroy()

    @staticmethod
    def onError(method_name, error_message):
        raise QueryProcessException(f"Error occurred during executing UDTF#{method_name}: {error_message}")

class UDFRegistrationService:
    @staticmethod
    def reflect(expression):
        # implementation of the method goes here

class ElasticSerializableTVList:
    @classmethod
    def new_elastic_serializable_tv_list(cls, output_data_type, query_id, collector_memory_budget_in_mb, batch_size):
        return cls(output_data_type, query_id, collector_memory_budget_in_mb, batch_size)

class UDFParameters:
    def __init__(self, expression, expression_data_type_map):
        self.expression = expression
        self.expression_data_type_map = expression_data_type_map

class UDTFConfigurations:
    def __init__(self):
        pass

    def get_output_data_type(self):
        # implementation of the method goes here

    def check(self):
        # implementation of the method goes here

class QueryProcessException(Exception):
    pass
