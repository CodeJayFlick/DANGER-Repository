class SBTypeEnumMemberList:
    def __init__(self):
        self._swig_cptr = None
        self._swig_cmemoown = False

    @property
    def _swig_cptr(self):
        return self._swig_cptr

    @_swig_cptr.setter
    def _swig_cptr(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Invalid cPtr")
        self._swig_cptr = value

    @property
    def _swig_cmemoown(self):
        return self._swig_cmemoown

    @_swicmcmemoown.setter
    def _swig_cmemoown(self, value):
        if not isinstance(value, bool):
            raise ValueError("Invalid cMemoryOwn")
        self._swig_cmemoown = value

    @property
    def IsValid(self):
        return lldbJNI.SBTypeEnumMemberList_IsValid(self._swig_cptr)

    def Append(self, entry):
        lldbJNI.SBTypeEnumMemberList_Append(self._swig_cptr, this, SBTypeEnumMember.getCPtr(entry), entry)

    def GetTypeEnumMemberAtIndex(self, index):
        return SBTypeEnumMember(lldbJNI.SBTypeEnumMemberList_GetTypeEnumMemberAtIndex(self._swig_cptr, self, index))

    @property
    def GetSize(self):
        return lldbJNI.SBTypeEnumMemberList_GetSize(self._swig_cptr)

# You can use the class like this:
my_list = SBTypeEnumMemberList()
if my_list.IsValid():
    # do something with your list

entry1 = SBTypeEnumMember()  # create an entry
entry2 = SBTypeEnumMember()

my_list.Append(entry1)
my_list.Append(entry2)

print(my_list.GetSize)  # print the size of the list

# You can also use it like this:
def delete(self):
    if self._swig_cptr != 0:
        lldbJNI.delete_SBTypeEnumMemberList(self._swig_cptr)
        self._swig_cmemoown = False
        self._swig_cptr = 0

SBTypeEnumMemberList.__del__ = delete
