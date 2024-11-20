import os
from datetime import datetime as dt

class LogReplayerTest:
    def __init__(self):
        pass

    @staticmethod
    def before():
        # Environment setup
        pass

    @staticmethod
    def after(modF, tsFileResource):
        try:
            modF.close()
            log_node_prefix = "testLogNode"
            os.remove(os.path.join(log_node_prefix + tsFile.name))
            os.rmdir(tsFile.parent)
        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def test():
        log_node_prefix = "testLogNode"
        ts_file_path = "temp/1-1-1.tsfile"
        mod_f_path = "test.mod"

        try:
            # Create timeseries and measurement nodes
            for i in range(6):
                for j in range(6):
                    IoTDB.meta_manager.create_timeseries(PartialPath(f"root.sg/device{i}/sensor{j}"), TSDataType.INT64, TSEncoding.PLAIN)

            replayer = LogReplayer(log_node_prefix, ts_file_path, mod_f_path)
            node = MultiFileLogNodeManager.get_instance().get_node(os.path.join(log_node_prefix + tsFile.name), lambda: [ByteBuffer.allocate_direct(IoTDBDescriptor.get_instance().config.wal_buffer_size // 2) for _ in range(2)])

            # Write data to log
            node.write(InsertRowPlan(PartialPath("root.sg/device0"), 100, "sensor0", TSDataType.INT64, str(0)))
            node.write(InsertRowPlan(PartialPath("root.sg/device0"), 2, "sensor1", TSDataType.INT64, str(0)))
            for i in range(4):
                node.write(InsertRowPlan(PartialPath(f"root.sg/device{i+1}"), i + 1, f"sensors{i+1}", TSDataType.INT64, str(i + 1)))

            # Write insert tablet
            for i in range(2):
                node.write(insert_tablet_plan())

        finally:
            mod_file = ModificationFile(mod_f_path)
            try:
                replayer.replay_logs(lambda: [ByteBuffer.allocate_direct(IoTDBDescriptor.get_instance().config.wal_buffer_size // 2) for _ in range(2)])
            except Exception as e:
                print(f"Error replaying logs: {e}")

    @staticmethod
    def insert_tablet_plan():
        measurements = ["sensor0", "sensor1"]
        data_types = [TSDataType.BOOLEAN.ordinal(), TSDataType.INT64.ordinal()]
        device_id = "root.sg/device5"

        m_nodes = [MeasurementMNode.get_measurement_mnode(None, measurement, None, None) for measurement in measurements]

        insert_tablet_plan = InsertTabletPlan(PartialPath(device_id), measurements, data_types)

        times = [i for i in range(100)]
        columns = [[False] * 100, [i for i in range(100)]]
        insert_tablet_plan.set_times(times)
        insert_tablet_plan.set_columns(columns)
        insert_tablet_plan.set_row_count(len(times))
        insert_tablet_plan.set_measurement_mnodes(m_nodes)
        insert_tablet_plan.set_start(0)
        insert_tablet_plan.set_end(100)

        return insert_tablet_plan

if __name__ == "__main__":
    LogReplayerTest().test()
