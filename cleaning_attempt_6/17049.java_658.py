import logging
from typing import List, Dict, Any

class TriggerRegistrationService:
    def __init__(self):
        self.executors: Dict[str, 'TriggerExecutor'] = {}
        self.log_writer: Any = None

    @staticmethod
    def get_instance():
        if not hasattr(TriggerRegistrationService, "instance"):
            TriggerRegistrationService.instance = TriggerRegistrationService()
        return TriggerRegistrationService.instance

    def register(self, plan: 'CreateTriggerPlan') -> None:
        check_if_registered(plan)
        measurement_mnode = try_get_measurement_mnode(plan)
        try_append_registration_log(plan)
        do_register(plan, measurement_mnode)

    @staticmethod
    def check_if_registered(plan: 'CreateTriggerPlan') -> None:
        if plan.get_trigger_name() in TriggerRegistrationService.instance.executors:
            raise TriggerManagementException(
                f"Failed to register trigger {plan.get_trigger_name()}({plan.get_class_name()}), because a trigger with the same name and class has already been registered.")

    @staticmethod
    def try_get_measurement_mnode(plan: 'CreateTriggerPlan') -> Any:
        try:
            return IoTDB.meta_manager.get_measurement_mnode(plan.get_full_path())
        except MetadataException as e:
            raise TriggerManagementException(str(e))

    @staticmethod
    def try_append_registration_log(plan: 'CreateTriggerPlan') -> None:
        try:
            log_writer = plan.log_writer()
            log_writer.write(plan)
        except IOException as e:
            raise TriggerManagementException(f"Failed to append trigger management operation log when registering trigger {plan.get_trigger_name()}, because {e}")

    @staticmethod
    def do_register(plan: 'CreateTriggerPlan', measurement_mnode: Any) -> None:
        information = plan.registration_information()
        class_loader = TriggerClassLoaderManager.instance().register(plan.get_class_name())

        executor = TriggerExecutor(information, class_loader, measurement_mnode)
        try:
            executor.on_create()
        except (TriggerManagementException, TriggerExecutionException as e):
            TriggerClassLoaderManager.instance().deregister(plan.get_class_name())
            raise e

        TriggerRegistrationService.instance.executors[plan.get_trigger_name()] = executor
        measurement_mnode.set_trigger_executor(executor)

    def deregister(self, plan: 'DropTriggerPlan') -> None:
        get_trigger_executor_with_existence_check(plan.get_trigger_name())
        try_append_deregistration_log(plan)
        do_deregister(plan)

    @staticmethod
    def get_trigger_executor_with_existence_check(trigger_name: str) -> Any:
        if trigger_name not in TriggerRegistrationService.instance.executors:
            raise TriggerManagementException(f"Trigger {trigger_name} does not exist.")
        return TriggerRegistrationService.instance.executors[trigger_name]

    @staticmethod
    def try_append_deregistration_log(plan: 'DropTriggerPlan') -> None:
        try:
            log_writer = plan.log_writer()
            log_writer.write(plan)
        except IOException as e:
            raise TriggerManagementException(f"Failed to drop trigger {plan.get_trigger_name()} because the operation plan was failed to log: {e}")

    @staticmethod
    def do_deregister(plan: 'DropTriggerPlan') -> None:
        executor = get_trigger_executor_with_existence_check(plan.get_trigger_name())
        try:
            executor.on_drop()
        except TriggerExecutionException as e:
            logging.warn(f"Failed to stop the executor of trigger {executor.registration_information().get_trigger_name()}({executor.registration_information().get_class_name()}) because {e}")

    def activate(self, plan: 'StartTriggerPlan') -> None:
        get_trigger_executor_with_existence_check(plan.get_trigger_name())
        if not executor.registration_information().is_stopped():
            raise TriggerManagementException(f"Failed to start trigger {plan.get_trigger_name()}({plan.get_class_name()}) because it has already been started.")
        try_append_activation_log(plan)
        do_activate(plan)

    @staticmethod
    def try_append_activation_log(plan: 'StartTriggerPlan') -> None:
        try:
            log_writer = plan.log_writer()
            log_writer.write(plan)
        except IOException as e:
            raise TriggerManagementException(f"Failed to append trigger management operation log when starting trigger {plan.get_trigger_name()}, because {e}")

    @staticmethod
    def do_activate(plan: 'StartTriggerPlan') -> None:
        executor = get_trigger_executor_with_existence_check(plan.get_trigger_name())
        try:
            executor.on_start()
        except TriggerExecutionException as e:
            logging.warn(f"Failed to start the executor of trigger {executor.registration_information().get_trigger_name()}({executor.registration_information().get_class_name()}) because {e}")

    def inactivate(self, plan: 'StopTriggerPlan') -> None:
        get_trigger_executor_with_existence_check(plan.get_trigger_name())
        if not executor.registration_information().is_stopped():
            raise TriggerManagementException(f"Failed to stop trigger {plan.get_trigger_name()}({plan.get_class_name()}) because it has already been stopped.")
        try_append_inactivation_log(plan)
        do_inactivate(plan)

    @staticmethod
    def try_append_inactivation_log(plan: 'StopTriggerPlan') -> None:
        try:
            log_writer = plan.log_writer()
            log_writer.write(plan)
        except IOException as e:
            raise TriggerManagementException(f"Failed to append trigger management operation log when stopping trigger {plan.get_trigger_name()}, because {e}")

    @staticmethod
    def do_inactivate(plan: 'StopTriggerPlan') -> None:
        executor = get_trigger_executor_with_existence_check(plan.get_trigger_name())
        try:
            executor.on_stop()
        except TriggerExecutionException as e:
            logging.warn(f"Failed to stop the executor of trigger {executor.registration_information().get_trigger_name()}({executor.registration_information().get_class_name()}) because {e}")

    def show(self) -> Any:
        data_set = ListDataSet(
            [PartialPath(COLUMN_TRIGGER_NAME, False), PartialPath(COLUMN_TRIGGER_STATUS, False),
             PartialPath(COLUMN_TRIGGER_EVENT, False), PartialPath(COLUMN_TRIGGER_PATH, False),
             PartialPath(COLUMN_TRIGGER_CLASS, False), PartialPath(COLUMN_TRIGGER_ATTRIBUTES, False)],
            [[TSDataType.TEXT] * 6]
        )
        put_trigger_records(data_set)
        return data_set

    @staticmethod
    def put_trigger_records(data_set: Any) -> None:
        for executor in TriggerRegistrationService.instance.executors.values():
            information = executor.registration_information()
            row_record = RowRecord(0, False)  # ignore timestamp
            row_record.add_field(Binary.valueOf(information.get_trigger_name()), TSDataType.TEXT)
            row_record.add_field(
                Binary.valueOf(information.is_stopped() and COLUMN_TRIGGER_STATUS_STOPPED or COLUMN_TRIGGER_STATUS_STARTED),
                TSDataType.TEXT)
            row_record.add_field(Binary.valueOf(str(information.get_event())), TSDataType.TEXT)
            row_record.add_field(Binary.valueOf(information.get_full_path().get_full_path()), TSDataType.TEXT)
            row_record.add_field(Binary.valueOf(information.get_class_name()), TSDataType.TEXT)
            row_record.add_field(Binary.valueOf(str(information.get_attributes())), TSDataType.TEXT)
            data_set.put_record(row_record)

    def start(self) -> None:
        try:
            make_dir_if_necessary(LIB_ROOT)
            do_recovery()
            self.log_writer = TriggerLogWriter(LOG_FILE_NAME)
        except Exception as e:
            raise StartupException(str(e))

    @staticmethod
    def make_dir_if_necessary(dir: str) -> None:
        file = SystemFileFactory.instance().get_file(dir)
        if not file.exists() or not file.is_directory():
            FileUtils.force_mkdir(file)

    @staticmethod
    def do_recovery() -> None:
        temporary_log_file = SystemFileFactory.instance().get_file(TEMPORARY_LOG_FILE_NAME)
        log_file = SystemFileFactory.instance().get_file(LOG_FILE_NAME)

        if temporary_log_file.exists():
            if log_file.exists():
                do_recovery_from_log_file(log_file)
                FileUtils.delete_quietly(temporary_log_file)
            else:
                do_recovery_from_log_file(temporary_log_file)
                FSFactoryProducer.get_fs_factory().move_file(temporary_log_file, log_file)

        elif log_file.exists():
            do_recovery_from_log_file(log_file)

    @staticmethod
    def do_recovery_from_log_file(file: Any) -> None:
        for create_trigger_plan in recover_create_trigger_plans(file):
            try:
                do_register(create_trigger_plan, try_get_measurement_mnode(create_trigger_plan))
                if create_trigger_plan.is_stopped():
                    TriggerRegistrationService.instance.executors[create_trigger_plan.get_trigger_name()].on_stop()
            except (TriggerExecutionException, TriggerManagementException as e):
                logging.error(f"Failed to register the trigger {create_trigger_plan.get_trigger_name()}({create_trigger_plan.get_class_name()}) during recovering because {e}")

    @staticmethod
    def recover_create_trigger_plans(file: Any) -> List[Any]:
        map = {}
        try:
            with TriggerLogReader(file):
                while has_next():
                    plan = next()
                    if isinstance(plan, CreateTriggerPlan):
                        map[plan.get_trigger_name()] = plan
                    elif isinstance(plan, DropTriggerPlan):
                        del map[plan.get_trigger_name()]
                    elif isinstance(plan, StartTriggerPlan) or isinstance(plan, StopTriggerPlan):
                        pass  # ignore start and stop plans during recovering

        except IOException as e:
            raise TriggerManagementException(str(e))

    def write_temporary_log_file(self) -> None:
        try:
            with TriggerLogWriter(TEMPORARY_LOG_FILE_NAME()) as log_writer:
                for executor in self.executors.values():
                    information = executor.registration_information()
                    log_writer.write(information.convert_to_create_trigger_plan())
                    if not information.is_stopped():
                        log_writer.write(DropTriggerPlan(information.get_trigger_name()))
        except IOException as e:
            raise TriggerManagementException(f"Failed to write temporary log file because {e}")

    @staticmethod
    def get_instance() -> Any:
        return TriggerRegistrationService()

    def deregister_all(self) -> None:
        for executor in self.executors.values():
            deregister(DropTriggerPlan(executor.registration_information().get_trigger_name()))

    def get_trigger_instance(self, trigger_name: str) -> Any:
        return get_trigger_executor_with_existence_check(trigger_name)

    def get_registration_information(self, trigger_name: str) -> Any:
        return get_trigger_executor_with_existence_check(trigger_name).registration_information()

class TriggerRegistrationInformation:
    pass

class TriggerExecutor:
    pass
