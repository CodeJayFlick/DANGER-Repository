class CaptureFunctionDataTypesListener:
    def __init__(self):
        pass

    def capture_function_data_types_completed(self, cmd):
        """
        Notification that the capture function data types command completed
        @param cmd: command that was completed; the command has the 
                    status as to whether the capture was successful
        """
        # Add your implementation here if needed
        pass


# Example usage:
class MyCaptureFunctionDataTypesListener(CaptureFunctionDataTypesListener):
    def __init__(self, success_callback=None, failure_callback=None):
        self.success_callback = success_callback
        self.failure_callback = failure_callback

    def capture_function_data_types_completed(self, cmd):
        if cmd.status:  # Assuming 'status' is a boolean indicating whether the capture was successful
            if self.success_callback:
                self.success_callback(cmd)
        else:
            if self.failure_callback:
                self.failure_callback(cmd)


# Usage example:
def on_capture_success(cmd):
    print(f"Capture function data types completed successfully with command {cmd}.")

def on_capture_failure(cmd):
    print(f"Capture function data types failed with command {cmd}.")

my_listener = MyCaptureFunctionDataTypesListener(on_capture_success, on_capture_failure)
