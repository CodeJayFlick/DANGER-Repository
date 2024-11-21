Here is the translation of the Java code to Python:

```Python
class PhysicalGenerator:
    def transform_to_physical_plan(self, operator):
        try:
            physical_plan = operator.generate_physical_plan(self)
            physical_plan.set_debug(operator.is_debug())
            return physical_plan
        except QueryProcessException as e:
            raise

    def generate_load_configuration_plan(self, type: LoadConfigurationOperatorType) -> PhysicalPlan:
        if type == LoadConfigurationOperatorType.GLOBAL:
            return LoadConfigurationPlan(LoadConfigurationPlanType.GLOBAL)
        elif type == LoadConfigurationOperatorType.LOCAL:
            return LoadConfigurationPlan(LoadConfigurationPlanType.LOCAL)
        else:
            raise QueryProcessException(f"Unrecognized load configuration operator type, {type.name}")

    def get_series_types(self, paths: List[PartialPath]) -> List[TSDataType]:
        try:
            return schema_utils.get_series_types_by_paths(paths)
        except MetadataException as e:
            raise

    def group_vector_paths(self, paths: List[PartialPath]) -> List[PartialPath]:
        try:
            return iotdb_meta_manager.group_vector_paths(paths)
        except MetadataException as e:
            raise
```

Note that I've used Python's type hinting to indicate the types of variables and function parameters. This is not strictly necessary, but it can make your code easier to read and understand.

Also note that in Python, we don't need to specify a return type for functions (like `public PhysicalPlan transformToPhysicalPlan(Operator operator)`), so I've omitted those.