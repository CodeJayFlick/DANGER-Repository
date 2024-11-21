import logging
from datetime import datetime

class PerformanceStatTest:

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @classmethod
    def setUp(cls):
        IoTDBDescriptor.getInstance().getConfig().setEnablePerformanceStat(True)

    @classmethod
    def tearDown(cls):
        IoTDBDescriptor.getInstance().getConfig().setEnablePerformanceStat(False)

    @staticmethod
    def test():
        measurement = Measurement.INSTANCE
        operation = Operation.EXECUTE_JDBC_BATCH
        start_time = datetime.now()
        end_time = start_time - datetime.timedelta(microseconds=8000000)
        measurement.add_operation_latency(operation, start_time)
        measurement.add_operation_latency(operation, end_time)

        batch_op_cnt = measurement.get_operation_cnt()[operation.ordinal()]
        assert batch_op_cnt == 0

        try:
            measurement.start()
            measurement.start_continuous_print_statistics()
            measurement.add_operation_latency(operation, datetime.now())
            measurement.add_operation_latenc(y=8000000)
            time.sleep(1)
            batch_op_cnt = measurement.get_operation_cnt()[operation.ordinal()]
            assert batch_op_cnt == 2
            measurement.stop_print_statistic()
            measurement.stop_print_statistic()
            measurement.stop_print_statistic()
            self.logger.info("After stopPrintStatistic!")
            time.sleep(1)
            measurement.clear_statistical_state()
            batch_op_cnt = measurement.get_operation_cnt()[operation.ordinal()]
            assert batch_op_cnt == 0
            measurement.start_continuous_print_statistics()
            self.logger.info("ReStart!")
            time.sleep(1)
            measurement.start_continuous_print_statistics()
            self.logger.info("ReStart2!")
            time.sleep(1)
            measurement.stop_print_statistic()
            self.logger.info("After stopStatistic2!")

        except Exception as e:
            self.logger.error(f"find error in stat performance, the message is {e.message}")

        finally:
            measurement.stop()

    @staticmethod
    def test_switch():
        try:
            measurement = Measurement.INSTANCE
            measurement.start()
            measurement.start_statistics()
            measurement.start_statistics()
            measurement.start_continuous_print_statistics()
            measurement.stop_print_statistic()
            measurement.stop_statistic()
            measurement.clear_statistical_state()
            measurement.start_print_statistics_once()
            measurement.start_continuous_print_statistics()
            measurement.start_statistics()

        except StartupException as e:
            e.print_stacktrace()

        finally:
            measurement.stop()


if __name__ == "__main__":
    PerformanceStatTest.setUp()
    try:
        # test
        PerformanceStatTest.test()
        # test_switch
        PerformanceStatTest.test_switch()
    finally:
        PerformanceStatTest.tearDown()
