import ctypes

class SBAttachInfo:
    def __init__(self):
        self._swig_cptr = 0
        self._swig_cmemoown = False

    @staticmethod
    def getCPtr(obj):
        return obj._swig_cptr if obj else 0

    def delete(self):
        if self._swig_cptr != 0:
            if self._swig_cmemoown:
                self._swig_cmemoown = False
                lldbJNI.delete_SBAttachInfo(self._swig_cptr)
            self._swig_cptr = 0

    @property
    def process_id(self):
        return ctypes.cast(self._swig_cptr, ctypes.py_object).value

    @process_id.setter
    def process_id(self, pid):
        lldbJNI.SBAttachInfo_SetProcessID(self._swig_cptr, self, pid)

    @property
    def executable_path(self):
        return ctypes.string_at(self._swig_cptr)

    @executable_path.setter
    def executable_path(self, path):
        lldbJNI.SBAttachInfo_SetExecutable__SWIG_0(self._swig_cptr, self, path)

    @property
    def wait_for_launch(self):
        return bool(ctypes.c_bool.from_address(self._swig_cptr))

    @wait_for_launch.setter
    def wait_for_launch(self, b):
        lldbJNI.SBAttachInfo_SetWaitForLaunch__SWIG_0(self._swig_cptr, self, b)

    @property
    def ignore_existing(self):
        return bool(ctypes.c_bool.from_address(self._swig_cptr))

    @ignore_existing.setter
    def ignore_existing(self, b):
        lldbJNI.SBAttachInfo_SetIgnoreExisting(self._swig_cptr, self, b)

    @property
    def resume_count(self):
        return ctypes.c_long.from_address(self._swig_cptr).value

    @resume_count.setter
    def resume_count(self, c):
        lldbJNI.SBAttachInfo_SetResumeCount(self._swig_cptr, self, c)

    @property
    def process_plugin_name(self):
        return ctypes.string_at(self._swig_cptr)

    @process_plugin_name.setter
    def process_plugin_name(self, plugin_name):
        lldbJNI.SBAttachInfo_SetProcessPluginName(self._swig_cptr, self, plugin_name)

    @property
    def user_id(self):
        return ctypes.c_long.from_address(self._swig_cptr).value

    @user_id.setter
    def user_id(self, uid):
        lldbJNI.SBAttachInfo_SetUserID(self._swig_cptr, self, uid)

    @property
    def group_id(self):
        return ctypes.c_long.from_address(self._swig_cptr).value

    @group_id.setter
    def group_id(self, gid):
        lldbJNI.SBAttachInfo_SetGroupID(self._swig_cptr, self, gid)

    @property
    def effective_user_id(self):
        return ctypes.c_long.from_address(self._swig_cptr).value

    @effective_user_id.setter
    def effective_user_id(self, uid):
        lldbJNI.SBAttachInfo_SetEffectiveUserID(self._swig_cptr, self, uid)

    @property
    def effective_group_id(self):
        return ctypes.c_long.from_address(self._swig_cptr).value

    @effective_group_id.setter
    def effective_group_id(self, gid):
        lldbJNI.SBAttachInfo_SetEffectiveGroupID(self._swig_cptr, self, gid)

    @property
    def parent_process_id(self):
        return ctypes.py_object(ctypes.cast(self._swig_cptr, ctypes.py_object).value)

    @parent_process_id.setter
    def parent_process_id(self, pid):
        lldbJNI.SBAttachInfo_SetParentProcessID(self._swig_cptr, self, pid)

    @property
    def listener(self):
        return SBListener(lldbJNI.SBAttachInfo_GetListener(self._swig_cptr, self), True)

    @listener.setter
    def listener(self, listener):
        lldbJNI.SBAttachInfo_SetListener(self._swig_cptr, self, SBListener.getCPtr(listener), listener)
