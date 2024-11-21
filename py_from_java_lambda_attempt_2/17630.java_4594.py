Here is the translation of the Java code to Python:
```python
import logging
from concurrent.futures import ThreadPoolExecutor
from atomic import AtomicInteger

class UpgradeService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.upgrade_thread_pool = None
        self.thread_cnt = AtomicInteger(0)
        self.cnt_upgrade_file_num = AtomicInteger(0)

    @classmethod
    def get_instance(cls):
        return _InstanceHolder.INSTANCE

class _InstanceHolder:
    INSTANCE = UpgradeService()

    def __init__(self):
        pass

def start(self):
    update_thread_num = IoTDBDescriptor.get_instance().get_config().get_upgrade_thread_num()
    if update_thread_num <= 0:
        update_thread_num = 1
    self.upgrade_thread_pool = ThreadPoolExecutor(max_workers=update_thread_num)
    UpgradeLog.create_upgrade_log()
    count_upgrade_files(self)
    if self.cnt_upgrade_file_num.get() == 0:
        stop(self)
        return
    upgrade_all()

def stop(self):
    UpgradeLog.close_log_writer()
    UpgradeUtils.clear_upgrade_recover_map()
    if self.upgrade_thread_pool is not None:
        self.upgrade_thread_pool.shutdown()
        logging.info("Waiting for upgrade task pool to shut down")
        self.upgrade_thread_pool = None
        logging.info("Upgrade service stopped")

def get_id(self):
    return ServiceType.UPGRADE_SERVICE

@classmethod
def get_total_upgrade_file_num(cls):
    return _InstanceHolder.INSTANCE.cnt_upgrade_file_num

def submit_upgrade_task(self, upgrade_task):
    self.upgrade_thread_pool.submit(upgrade_task)

def count_upgrade_files():
    UpgradeService.get_instance().cnt_upgrade_file_num.addAndGet(StorageEngine.get_instance().count_upgrade_files())
    logging.info("Finish counting upgrading files, total num: {}".format(UpgradeService.get_instance().cnt_upgrade_file_num))

def upgrade_all():
    try:
        StorageEngine.get_instance().upgrade_all()
    except StorageEngineException as e:
        logging.error("Cannot perform a global upgrade because", e)

if __name__ == "__main__":
    UpgradeService.get_instance().start()

# Note: The above code assumes that the following classes and functions are defined elsewhere in your Python program:

* IoTDBDescriptor
* UpgradeLog
* UpgradeUtils
* StorageEngine
* ServiceType

These classes and functions would need to be implemented or imported from a library for this code to work.