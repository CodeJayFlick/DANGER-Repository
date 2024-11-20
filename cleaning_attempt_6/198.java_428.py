class ThreadState:
    UNKNOWN = "The last recorded state is alive, but the recorder is not tracking the live thread"
    ALIVE = "The last recorded state is alive, but there is no live session to know STOPPED or RUNNING"
    STOPPED = "The thread is alive, but suspended"
    RUNNING = "The thread is alive and running"
    TERMINATED = "The thread has been terminated (either as recorded, or as reported by the live session)"
