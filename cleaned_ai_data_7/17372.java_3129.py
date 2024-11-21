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
