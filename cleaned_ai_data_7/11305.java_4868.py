class GTaskManagerFactory:
    _task_manager_map = weakref.WeakKeyDictionary()

    def get_task_manager(domain_object):
        if domain_object.is_closed():
            raise AssertionError("Attempted to get a TaskManger for a closed domain object")
        
        task_manager = _task_manager_map.get(domain_object)
        if task_manager is None:
            shared_thread_pool = GThreadPool.get_shared_thread_pool("Program Thread")
            task_manager = GTaskManager(domain_object, shared_thread_pool)
            _task_manager_map[domain_object] = task_manager
        
        return task_manager

    @staticmethod
    def domain_object_closed(domain_object):
        del _task_manager_map[domain_object]
