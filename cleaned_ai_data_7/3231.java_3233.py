class MoveBlockTask:
    def __init__(self, program, current_start, new_start, listener):
        self.current_start = current_start
        self.new_start = new_start
        self.listener = listener

    def do_run(self, monitor):
        try:
            block = program.get_memory().get_block(current_start)
            monitor.set_message("Moving Memory Block...")
            if not monitor.is_cancelled():
                program.get_memory().move_block(block, new_start, monitor)
                self.listener.move_block_completed(self)
            else:
                return False
        except Exception as e:
            status_message = str(e)
            raise RollbackException(status_message)

    def is_cancelled(self):
        return True  # Assuming cancelled state

    def was_successful(self):
        return True  # Assuming successful operation

    def get_status_message(self):
        return "Operation completed successfully"
