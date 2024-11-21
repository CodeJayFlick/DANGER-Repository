# Apache License v2.0 (http://www.apache.org/licenses/LICENSE-2.0)
class IDebugDataSpaces3:
    IID_IDEBUG_DATA_SPACES3 = "23f79d6c-8aaf-4f7c-a607-9995f5407e63"

    class VTIndices3:
        READ_IMAGE_NT_HEADERS = 1
        READ_TAGGED = 2
        START_ENUM_TAGGED = 3
        GET_NEXT_TAGGED = 4
        END_ENUM_TAGGED = 5

VTIndices3.start = VTIndices2.follow(VTIndices2.class)

def get_index(self):
    return self.ordinal() + VTIndices2.follow(VTIndices2.class)
