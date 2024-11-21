import os
import threading
from io import BytesIO
from typing import Optional

class ExclusiveWriteLogNode:
    WAL_FILE_NAME = "wal"
    logger = logging.getLogger(__name__)

    def __init__(self, identifier: str):
        self.identifier = identifier
        self.log_directory = os.path.join(DirectoryManager.get_wal_folder(), identifier)
        if not os.makedirs(self.log_directory, exist_ok=True):
            self.logger.info("create the WAL folder {}".format(self.log_directory))
        
        self.current_file_writer: Optional[ILogWriter] = None
        self.file_id = 0
        self.last_flushed_id = 0
        self.buffered_log_num = 0

    def init_buffer(self, byte_buffers):
        self.log_buffer_working = byte_buffers[0]
        self.log_buffer_idle = byte_buffers[1]

    def write(self, plan: PhysicalPlan) -> None:
        if deleted.get():
            raise IOException("WAL node deleted")
        
        lock.acquire()
        try:
            put_log(plan)
            if buffered_log_num >= config.get_flush_wal_threshold():
                sync()
        except BufferOverflowException as e:
            log_buffer_working.truncate(0)
            self.logger.error("Log cannot fit into the buffer, please increase wal_buffer_size", e)
        finally:
            lock.release()

    def put_log(self, plan: PhysicalPlan) -> None:
        log_buffer_working.mark()
        try:
            plan.serialize(log_buffer_working)
        except BufferOverflowException as e:
            log_buffer_working.reset()
            sync()
            plan.serialize(log_buffer_working)

        buffered_log_num += 1

    def close(self):
        sync()
        force_wal()

        lock.acquire()
        try:
            while self.log_buffer_flushing is not None and not deleted.get():
                switch_buffer_condition.wait()
            
            switch_buffer_condition.notify_all()
        
        finally:
            if self.current_file_writer is not None:
                self.current_file_writer.close()
                self.logger.debug("WAL file {} is closed".format(self.current_file_writer))
                self.current_file_writer = None
            lock.release()

    def force_sync(self) -> None:
        sync()
        force_wal()

    def notify_start_flush(self):
        lock.acquire()
        try:
            close()
            next_file_writer()
        finally:
            lock.release()

    def notify_end_flush(self):
        lock.acquire()
        try:
            log_file = os.path.join(self.log_directory, WAL_FILE_NAME + str(last_flushed_id))
            discard(log_file)
        finally:
            lock.release()

    def get_identifier(self) -> str:
        return self.identifier

    def get_log_directory(self) -> str:
        return self.log_directory

    def delete(self):
        lock.acquire()
        try:
            close()
            FileUtils.delete_directory(os.path.join(self.log_directory))
            deleted.set(True)
            return [self.buffer_array]
        finally:
            FLUSH_BUFFER_THREAD_POOL.shutdown()
            lock.release()

    def get_log_reader(self) -> ILogReader:
        log_files = os.listdir(self.log_directory)
        log_files.sort(key=lambda f: int(f.replace(WAL_FILE_NAME, "")))
        return MultiFileLogReader(log_files)

    def discard(self, log_file):
        if not os.path.exists(log_file):
            self.logger.info("Log file does not exist")
        else:
            try:
                FileUtils.force_delete(log_file)
                self.logger.info("Log node {} cleaned old file".format(self.identifier))
            except IOException as e:
                self.logger.warn("Old log file {} of {} cannot be deleted", log_file, self.identifier, e)

    def force_wal(self):
        lock.acquire()
        try:
            if self.current_file_writer is not None:
                self.current_file_writer.force()
        finally:
            lock.release()

    def sync(self) -> None:
        lock.acquire()
        try:
            while buffered_log_num == 0:
                return
            
            switch_buffer_working_to_flushing()
            curr_writer = get_current_file_writer()
            FLUSH_BUFFER_THREAD_POOL.submit(flush_buffer, (curr_writer,))
            
            buffered_log_num = 0
            self.logger.debug("Log node {} ends sync".format(self.identifier))
        except InterruptedException as e:
            Thread.currentThread().interrupt()
            self.logger.warn("Waiting for available buffer interrupted")
        finally:
            lock.release()

    def flush_buffer(self, writer):
        try:
            writer.write(log_buffer_flushing)
        except ClosedChannelException:
            pass
        except IOException as e:
            self.logger.error("Log node {} sync failed, change system mode to read-only".format(self.identifier), e)
            IoTDBDescriptor.get_instance().get_config().set_read_only(True)

        # switch buffer flushing to idle and notify the sync thread
        lock.acquire()
        try:
            log_buffer_idle = log_buffer_flushing
            log_buffer_flushing = None
            switch_buffer_condition.notify_all()
        finally:
            lock.release()

    def switch_buffer_working_to_flushing(self):
        lock.acquire()
        while log_buffer_flushing is not None and not deleted.get():
            switch_buffer_condition.wait(100)
        
        log_buffer_flushing = log_buffer_working
        log_buffer_working = log_buffer_idle
        log_buffer_idle = None

    def get_current_file_writer(self) -> ILogWriter:
        if self.current_file_writer is None:
            next_file_writer()
        return self.current_file_writer

    def next_file_writer(self):
        self.file_id += 1
        new_file = os.path.join(self.log_directory, WAL_FILE_NAME + str(self.file_id))
        
        try:
            os.makedirs(os.path.dirname(new_file), exist_ok=True)
            self.logger.debug("WAL file {} is opened".format(new_file))
            
            self.current_file_writer = LogWriter(new_file, config.get_force_wal_period_in_ms() == 0)
        except IOException as e:
            self.logger.error("Cannot open WAL file", e)

    def __hash__(self):
        return hash(self.identifier)

    def __eq__(self, other):
        if not isinstance(other, ExclusiveWriteLogNode):
            return False
        
        return self.identifier == other.identifier

    def __str__(self) -> str:
        return "Log node {}".format(self.identifier)
