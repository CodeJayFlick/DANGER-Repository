import logging
from typing import Dict, Any

class SlotManager:
    def __init__(self, total_slot_number: int, member_dir: str, member_name: str):
        self.slot_file_path = f"{member_dir}/{SLOT_FILE_NAME}" if member_dir else None
        self.member_name = member_name
        self.id_slot_map = {}
        if not load():
            init(total_slot_number)

    def wait_slot(self, slot_id: int) -> None:
        while True:
            descriptor = self.id_slot_map.get(slot_id)
            if descriptor.slot_status in [SlotStatus.PULLING, SlotStatus.PULLING_WRITABLE]:
                try:
                    descriptor.wait(SLOT_WAIT_INTERVAL_MS)
                except KeyboardInterrupt as e:
                    logging.error("Unexpected interruption when waiting for slot %d", slot_id, e)
                break
            else:
                cost = (logging.current_milli_time() - start_time) if start_time is not None else 0
                if cost > SLOT_WAIT_THRESHOLD_MS:
                    logging.info("Wait slot %d cost %ms", slot_id, cost)
                return

    def wait_slot_for_write(self, slot_id: int) -> None:
        while True:
            descriptor = self.id_slot_map.get(slot_id)
            start_time = logging.current_milli_time()
            if descriptor.slot_status == SlotStatus.PULLING:
                try:
                    if (logging.current_milli_time() - start_time) >= SLOT_WAIT_THRESHOLD_MS:
                        raise StorageEngineException(f"The status of slot {slot_id} is still PULLING after 5s.")
                    descriptor.wait(SLOT_WAIT_INTERVAL_MS)
                except KeyboardInterrupt as e:
                    logging.error("Unexpected interruption when waiting for slot %d", slot_id, e)
            else:
                return

    def check_slot_in_data_migration_status(self, slot_id: int) -> bool:
        return self.id_slot_map.get(slot_id).slot_status in [SlotStatus.PULLING, SlotStatus.PULLING_WRITABLE]

    # ... (rest of the methods)

class StorageEngineException(Exception):
    pass

SLOT_FILE_NAME = "SLOT_STATUS"
SLOT_WAIT_INTERVAL_MS = 10
SLOT_WAIT_THRESHOLD_MS = 2000

logger = logging.getLogger(__name__)

def load() -> bool:
    if slot_file_path is None:
        return False
    try:
        with open(slot_file_path, 'rb') as file:
            buffer = bytearray(file.read())
            deserialize(buffer)
            return True
    except Exception as e:
        logger.warn("Cannot deserialize slotManager from %s", slot_file_path, e)
        return False

def save() -> None:
    if slot_file_path is None:
        return
    try:
        with open(slot_file_path, 'wb') as file:
            serialize(file)
    except Exception as e:
        logger.warn("SlotManager in %s cannot be saved", slot_file_path, e)

class SlotStatus(Enum):
    NULL = 0
    PULLING = 1
    PULLING_WRITABLE = 2
    SENDING = 3
    SENT = 4

class SlotDescriptor:
    def __init__(self) -> None:
        self.slot_status: SlotStatus = SlotStatus.NULL
        self.source: Any = None
        self.snapshot_received_count: int = 0

    @classmethod
    def deserialize(cls, buffer: bytearray) -> 'SlotDescriptor':
        descriptor = cls()
        descriptor.slot_status = SlotStatus(buffer[0])
        if descriptor.slot_status in [SlotStatus.PULLING, SlotStatus.PULLING_WRITABLE]:
            # ... (rest of the deserialization)
        return descriptor

    def serialize(self, file: Any) -> None:
        file.write(int(self.slot_status.value))
        if self.slot_status == SlotStatus.PULLING or self.slot_status == SlotStatus.PULLING_WRITABLE:
            NodeSerializeUtils.serialize(self.source, file)
        elif self.slot_status == SlotStatus.SENDING:
            file.write(int(self.snapshot_received_count))

    def wait(self, interval: int) -> None:
        # ... (wait implementation)

# usage
slot_manager = SlotManager(total_slot_number=1000, member_dir="/path/to/member", member_name="member1")
