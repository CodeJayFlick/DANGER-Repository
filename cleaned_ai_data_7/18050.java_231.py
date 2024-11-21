class Config:
    DEFAULT_HOST = "localhost"
    DEFAULT_PORT = 6667
    DEFAULT_USER = "root"
    DEFAULT_PASSWORD = "root"
    DEFAULT_FETCH_SIZE = 5000
    DEFAULT_CONNECTION_TIMEOUT_MS = 0
    DEFAULT_CACHE_LEADER_MODE = True

    CPU_CORES = runtime().available_processors()
    DEFAULT_SESSION_EXECUTOR_THREAD_NUM = 2 * CPU_CORES
    DEFAULT_SESSION_EXECUTOR_TASK_NUM = 1000

    RETRY_NUM = 3
    RETRY_INTERVAL_MS = 1000

    DEFAULT_INITIAL_BUFFER_CAPACITY = 1024
    DEFAULT_MAX_FRAME_SIZE = 67108864
    DEFAULT_SESSION_POOL_MAX_SIZE = 5


def runtime():
    import platform
    if platform.system() == "Windows":
        return platform.python_runtime()
    else:
        return None
