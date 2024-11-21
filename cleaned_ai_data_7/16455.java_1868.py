import logging
from typing import List

class BaseApplier:
    def __init__(self, meta_group_member: 'MetaGroupMember'):
        self.meta_group_member = meta_group_member
        self.query_executor = None
        self.logger = logging.getLogger(__name__)

    def apply_physical_plan(self, plan: 'PhysicalPlan', data_group_member: 'DataGroupMember') -> None:
        if isinstance(plan, InsertPlan):
            self.process_plan_with_tolerance(plan, data_group_member)
        elif plan is not None and not plan.is_query():
            try:
                self.query_executor.process_non_query(plan)
            except BatchProcessException as e:
                self.handle_batch_process_exception(e, plan, data_group_member)
            except (QueryProcessException, StorageGroupNotSetException, StorageEngineException) as e:
                if isinstance(e, QueryProcessException):
                    raise
                elif isinstance(e, StorageGroupNotSetException):
                    self.execute_after_sync(plan)
                else:
                    raise
        elif plan is not None:
            self.logger.error("Unsupported physical plan: {}", plan)

    def handle_batch_process_exception(self, e: BatchProcessException, plan: 'PhysicalPlan', data_group_member: 'DataGroupMember') -> None:
        if IoTDBDescriptor.getInstance().getConfig().is_enable_partition():
            failing_status = e.get_failing_status()
            for i in range(len(failing_status)):
                status = failing_status[i]
                # skip succeeded plans in later execution
                if status is not None and status.code == TSStatusCode.SUCCESS_STATUS.getStatusCode() and isinstance(plan, BatchPlan):
                    (BatchPlan) plan).set_is_executed(i)
                elif status is not None:
                    if status.code == TSStatusCode.TIMESERIES_NOT_EXIST.getStatusCode():
                        self.logger.info("{} doesn't exist, it may has been deleted.", plan.get_paths().get(i))
                    else:
                        raise e
            need_retry = False
            for i in range(len(failing_status)):
                status = failing_status[i]
                if status is not None and (status.code == TSStatusCode.STORAGE_GROUP_NOT_EXIST.getStatusCode() or status.code == TSStatusCode.UNDEFINED_TEMPLATE.getStatusCode()):
                    ((BatchPlan) plan).unset_is_executed(i)
                    need_retry = True
            if need_retry:
                self.execute_after_sync(plan)

    def execute_after_sync(self, plan: 'PhysicalPlan') -> None:
        try:
            self.meta_group_member.sync_leader_with_consistency_check(True)
        except CheckConsistencyException as e:
            raise QueryProcessException(e.message)
        self.query_executor.process_non_query(plan)

    def process_plan_with_tolerance(self, plan: InsertPlan, data_group_member: 'DataGroupMember') -> None:
        try:
            self.query_executor.process_non_query(plan)
        except BatchProcessException as e:
            self.handle_batch_process_exception(e, plan, data_group_member)
        except (QueryProcessException, StorageGroupNotSetException, StorageEngineException) as e:
            if IoTDBDescriptor.getInstance().getConfig().is_enable_partition():
                meta_missing_exception = SchemaUtils.find_meta_missing_exception(e)
                caused_by_path_not_exist = isinstance(meta_missing_exception, PathNotExistException)

                if caused_by_path_not_exist:
                    self.logger.debug("Timeseries is not found locally[{}], try pulling it from another group: {}", data_group_member.name(), e.cause().message)
                    self.pull_timeseries_schema(plan, data_group_member.header())
                    plan.recover_from_failure()
                    self.query_executor.process_non_query(plan)

    def pull_timeseries_schema(self, plan: 'PhysicalPlan', ignored_group) -> None:
        try:
            if isinstance(plan, BatchPlan):
                MetaPuller.getInstance().pull_time_series_schemas(((BatchPlan) plan).get_prefix_paths(), ignored_group)
            else:
                partial_path = plan.get_prefix_path()
                MetaPuller.getInstance().pull_time_series_schemas([partial_path], ignored_group)
        except MetadataException as e1:
            raise QueryProcessException(e1)

    def get_query_executor(self) -> 'PlanExecutor':
        if self.query_executor is None:
            self.query_executor = ClusterPlanExecutor(self.meta_group_member)
        return self.query_executor

    @TestOnly
    def set_query_executor(self, query_executor: 'PlanExecutor'):
        self.query_executor = query_executor


class MetaGroupMember:

    # methods and properties of the class


class DataGroupMember:

    # methods and properties of the class


class PhysicalPlan:

    # methods and properties of the class


class InsertPlan(PhysicalPlan):

    # methods and properties of the class


class BatchProcessException(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    def get_failing_status(self) -> List[TSStatus]:
        return []

    @property
    def code(self) -> int:
        pass

    @code.setter
    def code(self, value: int):
        self._code = value


class TSStatusCode:

    # methods and properties of the class


# Define other classes as needed.
