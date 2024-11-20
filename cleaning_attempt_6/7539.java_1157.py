class LazyGraphRegroupSaveableXML:
    def __init__(self, function_graph):
        self.function_graph = function_graph

    def is_empty(self):
        group_history = self.function_graph.get_group_history()
        return len(group_history) == 0

    def save(self):
        try:
            xml_string = GroupVertexSerializer().get_xml_for_regroupable_vertices(self.function_graph)
        except Exception as e:
            Msg.error("Unable to save XML data.", e)

        obj_storage.put_string(xml_string)


class ObjectStorage:
    @staticmethod
    def put_string(s):
        pass


class GenericXMLOutputter:
    @staticmethod
    def output(document, stream):
        pass


from collections import Collection

class GroupHistoryInfo:
    pass


class FunctionGraph:
    def get_group_history(self) -> Collection[GroupHistoryInfo]:
        return []
