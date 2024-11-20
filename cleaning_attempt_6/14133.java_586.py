# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class ThreadCompleteListener:
    """Interface with listener behaviour related to Thread Completion."""
    
    def completed_event_handler(self, event_id: int):
        pass
