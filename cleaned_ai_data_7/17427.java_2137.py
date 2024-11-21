class UDTFDataSet:
    def __init__(self):
        pass  # No direct constructor in Python as it's not needed.

    @staticmethod
    def get_udf_reader_memory_budget_in_mb():
        return IoTDBDescriptor.getInstance().getConfig().getUdfReaderMemoryBudgetInMB()

    @staticmethod
    def get_udf_transformer_memory_budget_in_mb():
        return IoTDBDescriptor.getInstance().getConfig().getUdfTransformerMemoryBudgetInMB()

    @staticmethod
    def get_udf_collector_memory_budget_in_mb():
        return IoTDBDescriptor.getInstance().getConfig().getUdfCollectorMemoryBudgetInMB()

    def __init__(self, query_context: 'QueryContext', udtf_plan: 'UDTFPlan',
                 deduplicated_paths: list['PartialPath'], deduplicated_data_types: list[TSDataType],
                 timestamp_generator: TimeGenerator,
                 readers_of_selected_series: list[IReaderByTimestamp], cached: list[bool]):
        super().__init__(deduplicated_paths, deduplicated_data_types)
        self.query_id = query_context.get_query_id()
        self.udtf_plan = udtf_plan
        self.raw_query_input_layer = RawQueryInputLayer(
            self.query_id,
            UDTFDataSet.get_udf_reader_memory_budget_in_mb(),
            deduplicated_paths,
            deduplicated_data_types,
            timestamp_generator,
            readers_of_selected_series,
            cached)

    def init_transformers(self):
        udf_registration_service_instance = UDFRegistrationService.getInstance()
        try:
            udf_registration_service_instance.acquire_registration_lock()

            # This statement must be surrounded by the registration lock.
            udf_class_loader_manager_instance = UDFClassLoaderManager.getInstance()
            udf_class_loader_manager_instance.initialize_udf_query(self.query_id)

            transformers = DAGBuilder(
                self.query_id,
                self.udtf_plan,
                self.raw_query_input_layer,
                UDTFDataSet.get_udf_transformer_memory_budget_in_mb() + UDTFDataSet.get_udf_collector_memory_budget_in_mb()
            ).build_layer_memory_assigner().build_result_column_point_readers().set_data_set_result_column_data_types().get_result_column_point_readers()

        finally:
            udf_registration_service_instance.release_registration_lock()

    def finalize_udfs(self, query_id: int):
        self.udtf_plan.finalize_udf_executors(query_id)

class RawQueryInputLayer:
    pass  # No direct constructor in Python as it's not needed.

class DAGBuilder:
    pass  # No direct constructor in Python as it's not needed.
