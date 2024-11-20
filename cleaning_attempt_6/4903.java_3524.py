class ResourceType:
    RT_CURSOR = 0x01
    RT_BITMAP = 0x02
    RT_ICON = 0x03
    RT_MENU = 0x04
    RT_DIALOG = 0x05
    RT_STRING = 0x06
    RT_FONTDIR = 0x07
    RT_FONT = 0x08
    RT_ACCELERATOR = 0x09
    RT_RCDATA = 0x0a
    RT_MESSAGETABLE = 0x0b
    RT_GROUP_CURSOR = 0x0c
    RT_VERSION = 0x10

    def __init__(self, reader):
        self.type_id = reader.read_short()
        if self.type_id == 0:
            return  # not a valid resource type...
        
        self.count = reader.read_short()
        self.reserved = reader.read_int()

        resources_list = []
        count_int = int(self.count)
        for i in range(count_int):
            if (self.type_id & 0x7fff) == ResourceType.RT_STRING:
                resources_list.append(ResourceStringTable(reader))
            else:
                resources_list.append(Resource(reader))

        self.resources = [Resource(x) for x in resources_list]

    def get_type_id(self):
        return self.type_id

    def get_count(self):
        return self.count

    def get_reserved(self):
        return self.reserved

    def get_resources(self):
        return self.resources


class Resource:
    pass  # abstract class, no implementation provided


class ResourceStringTable(Resource):
    pass  # abstract class, no implementation provided
