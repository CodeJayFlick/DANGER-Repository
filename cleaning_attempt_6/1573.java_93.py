class LldbSetActiveThreadCommand:
    def __init__(self, manager, thread, frame_id):
        self.manager = manager
        self.thread = thread
        self.frame_id = frame_id

    def invoke(self):
        process = self.manager.get_current_process()
        process.set_selected_thread(self.thread)
        if self.frame_id >= 0:
            selected_thread = process.get_selected_thread()
            selected_thread.set_selected_frame(self.frame_id)

# Usage example:

class LldbManagerImpl:
    def get_current_process(self): pass
    def set_selected_thread(self, thread): pass
    def get_selected_thread(self): pass

manager = LldbManagerImpl()

thread = SBThread()  # Assuming you have a class or function to create an instance of this type.
frame_id = 0  # Replace with your desired frame level.

command = LldbSetActiveThreadCommand(manager, thread, frame_id)
command.invoke()
