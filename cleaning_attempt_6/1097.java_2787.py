from ctypes import POINTER, HRESULT, c_bool, byref
import uuid

class IDynamicConceptProviderConcept:
    IID_IDYNAMIC_CONCEPT_PROVIDER_CONCEPT = uuid.UUID('95A7F7DD-602E-483f-9D06-A15C0EE13174')

    class VTIndices:
        GET_CONCEPT = 3
        SET_CONCEPT = 4
        NOTIFY_PARENT = 5
        NOTIFY_PARENT_CHANGE = 6
        NOTIFY_DESTRUCT = 7

    def GetConcept(self, contextObject, conceptId, conceptInterface, conceptMetadata, hasConcept):
        return HRESULT(0)

    def SetConcept(self, contextObject, conceptId, conceptInterface, conceptMetadata):
        return HRESULT(0)

    def NotifyParent(self, parentModel):
        return HRESULT(0)

    def NotifyParentChange(self, parentModel):
        return HRESULT(0)

    def NotifyDestruct(self):
        return HRESULT(0)
