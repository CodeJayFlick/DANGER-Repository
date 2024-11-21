class FlushManagerMBean:
    def get_number_of_working_tasks(self):
        raise NotImplementedError("Not implemented")

    def get_number_of_pending_tasks(self):
        raise NotImplementedError("Not implemented")

    def get_number_of_working_subtasks(self):
        raise NotImplementedError("Not implemented")

    def get_number_of_pending_subtasks(self):
        raise NotImplementedError("Not implemented")
