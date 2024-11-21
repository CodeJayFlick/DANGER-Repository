class DropFunctionOperator:
    def __init__(self):
        self.udf_name = None
        super().__init__()

    @property
    def udf_name(self):
        return self._udf_name

    @udf_name.setter
    def udf_name(self, value):
        self._udf_name = value

    def generate_physical_plan(self, generator) -> PhysicalPlan:
        from . import DropFunctionPlan
        return DropFunctionPlan(self.udf_name)

class PhysicalPlan:
    pass  # placeholder for a physical plan class

class QueryProcessException(Exception):
    pass  # placeholder for an exception class
