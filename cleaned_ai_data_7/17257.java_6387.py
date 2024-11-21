class LoadConfigurationOperator:
    def __init__(self, load_configuration_operator_type):
        self.load_configuration_operator_type = load_configuration_operator_type
        super().__init__()

    @property
    def load_configuration_operator_type(self):
        return self._load_configuration_operator_type

    @load_configuration_operator_type.setter
    def load_configuration_operator_type(self, value):
        self._load_configuration_operator_type = value

class LoadConfigurationOperatorType:
    LOCAL = 1
    GLOBAL = 2

    def __init__(self, value):
        if not isinstance(value, int) or value not in [LOCAL, GLOBAL]:
            raise ValueError("Invalid load configuration operator type")
        self.value = value

def generate_physical_plan(self, generator):
    try:
        return generator.generate_load_configuration_plan(self.load_configuration_operator_type)
    except Exception as e:
        raise QueryProcessException(str(e))

# Example usage
load_config_op = LoadConfigurationOperator(LoadConfigurationOperatorType.LOCAL)
physical_plan = load_config_op.generate_physical_plan(PhysicalGenerator())
