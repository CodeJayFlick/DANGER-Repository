class LocalIoTDBHandler:
    def __init__(self):
        self.executor = None
        self.device = None
        self.measurements = []
        self.data_types = []

    def open(self, configuration: dict) -> None:
        if 'device' not in configuration or 'measurements' not in configuration or 'data_types' not in configuration:
            raise Exception('Invalid configuration')

        self.executor = PlanExecutor()
        self.device = configuration['device']
        self.measurements = configuration['measurements']
        self.data_types = configuration['data_types']

        self.create_or_check_timeseries()

    def create_or_check_timeseries(self) -> None:
        for i, measurement in enumerate(self.measurements):
            path = f"{self.device}/{measurement}"
            if not IoTDB.meta_manager.is_path_exist(path):
                IoTDB.meta_manager.create_timeseries(
                    path,
                    self.data_types[i],
                    get_default_encoding(self.data_types[i]),
                    TSFileDescriptor.get_instance().get_config().get_compressor(),
                    {}
                )
            else:
                schema = IoTDB.meta_manager.get_series_schema(self.device, measurement)
                if schema['type'] != self.data_types[i]:
                    raise SinkException(f"Data type of {path} you provided was not correct.")

    def on_event(self, event: dict) -> None:
        plan = InsertRowPlan()
        plan.set_need_infer_type(False)
        plan.set_prefix_path(self.device)
        plan.set_measurements(self.measurements)
        plan.set_data_types(self.data_types)
        plan.set_time(event['timestamp'])
        plan.set_values(event['values'])
        self.execute_non_query(plan)

    def execute_non_query(self, plan: PhysicalPlan) -> None:
        if IoTDBDescriptor.get_instance().get_config().is_read_only():
            raise QueryProcessException("Current system mode is read-only, non-query operation is not supported.")
        self.executor.process_non_query(plan)
