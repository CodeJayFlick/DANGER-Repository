Here is a translation of the provided Java code into equivalent Python:

```Python
class WrapIDebugSystemObjects:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def get_event_thread(self, Id):
        return _invoke_hr(VTIndices.GET_EVENT_THREAD, self.pv_instance, Id)

    def get_event_process(self, Id):
        return _invoke_hr(VTIndices.GET_EVENT_PROCESS, self.pv_instance, Id)

    def get_current_thread_id(self, Id):
        return _invoke_hr(VTIndices.GET_CURRENT_THREAD_ID, self.pv_instance, Id)

    def set_current_thread_id(self, Id):
        return _invoke_hr(VTIndices.SET_CURRENT_THREAD_ID, self.pv_instance, Id)

    def get_current_process_id(self, Id):
        return _invoke_hr(VTIndices.GET_CURRENT_PROCESS_ID, self.pv_instance, Id)

    def set_current_process_id(self, Id):
        return _invoke_hr(VTIndices.SET_CURRENT_PROCESS_ID, self.pv_instance, Id)

    def get_number_threads(self, Number):
        return _invoke_hr(VTIndices.GET_NUMBER_THREADS, self.pv_instance, Number)

    def get_total_number_threads(self, Total, LargestProcess):
        return _invoke_hr(VTIndices.GET_TOTAL_NUMBER_THREADS, self.pv_instance, Total, LargestProcess)

    def get_thread_ids_by_index(self, Start, Count, Ids, SysIds):
        return _invoke_hr(VTIndices.GET_THREAD_IDS_BY_INDEX, self.pv_instance, Start, Count, Ids, SysIds)

    def get_thread_id_by_handle(self, Handle, Id):
        return _invoke_hr(VTIndices.GET_THREAD_ID_BY_HANDLE, self.pv_instance, Handle, Id)

    def get_thread_id_by_system_id(self, SystemId, Id):
        return _invoke_hr(VTIndices.GET_THREAD_ID_BY_SYSTEM_ID, self.pv_instance, SystemId, Id)

    def get_process_id_by_system_id(self, SystemId, Id):
        return _invoke_hr(VTIndices.GET_PROCESS_ID_BY_SYSTEM_ID, self.pv_instance, SystemId, Id)

    def get_number_processes(self, Number):
        return _invoke_hr(VTIndices.GET_NUMBER_PROCESSES, self.pv_instance, Number)

    def get_process_ids_by_index(self, Start, Count, Ids, SysIds):
        return _invoke_hr(VTIndices.GET_PROCESS_IDS_BY_INDEX, self.pv_instance, Start, Count, Ids, SysIds)

    def get_process_id_by_handle(self, Handle, Id):
        return _invoke_hr(VTIndices.GET_PROCESS_ID_BY_HANDLE, self.pv_instance, Handle, Id)

    def get_current_thread_system_id(self, SysId):
        return _invoke_hr(VTIndices.GET_CURRENT_THREAD_SYSTEM_ID, self.pv_instance, SysId)

    def get_current_process_system_id(self, SysId):
        return _invoke_hr(VTIndices.GET_CURRENT_PROCESS_SYSTEM_ID, self.pv_instance, SysId)


class ByReference(WrapIDebugSystemObjects):
    pass


def _invoke_hr(index, instance, *args):
    # implement the logic for invoking HR here
    pass

VTIndices = {
    'GET_EVENT_THREAD': 1,
    'GET_EVENT_PROCESS': 2,
    'GET_CURRENT_THREAD_ID': 3,
    'SET_CURRENT_THREAD_ID': 4,
    'GET_CURRENT_PROCESS_ID': 5,
    'SET_CURRENT_PROCESS_ID': 6,
    'GET_NUMBER_THREADS': 7,
    'GET_TOTAL_NUMBER_THREADS': 8,
    'GET_THREAD_IDS_BY_INDEX': 9,
    'GET_THREAD_ID_BY_HANDLE': 10,
    'GET_THREAD_ID_BY_SYSTEM_ID': 11,
    'GET_PROCESS_ID_BY_SYSTEM_ID': 12,
    'GET_NUMBER_PROCESSES': 13,
    'GET_PROCESS_IDS_BY_INDEX': 14,
    'GET_PROCESS_ID_BY_HANDLE': 15,
    'GET_CURRENT_THREAD_SYSTEM_ID': 16,
    'GET_CURRENT_PROCESS_SYSTEM_ID': 17
}
```

Please note that the Python code above is a direct translation of your Java code. However, you may need to adjust it based on how `_invoke_hr` function works in your actual application.

Also, this code does not include any error handling or exception management which might be necessary depending on the specific requirements and constraints of your project.