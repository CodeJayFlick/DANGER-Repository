import logging
from collections import defaultdict, OrderedDict

class TagManager:
    TAG_FORMAT = "tag key is %s, tag value is %s, tlog offset is %d"
    DEBUG_MSG = "%s : TimeSeries %s is removed from tag inverted index,"
    PREVIOUS_CONDITION = "before deleting it, tag key is %s, tag value is %s, tlog offset is %d, contains key %b"

    logger = logging.getLogger(__name__)
    config = None

    def __init__(self):
        self.tag_index = defaultdict(dict)
        self.tag_log_file = None
        self.config = IoTDBConfig()

    @staticmethod
    def get_instance():
        return TagManagerHolder.INSTANCE

    @staticmethod
    def get_new_instance_for_test():
        return TagManager()

    def init(self) -> None:
        if not self.tag_log_file:
            self.tag_log_file = TagLogFile(self.config.get_schema_dir(), "TAG_LOG")

    def add_index(self, tag_key: str, tag_value: str, measurement_m_node: IMeasurementMNode) -> None:
        if tag_key in self.tag_index and tag_value in self.tag_index[tag_key]:
            self.tag_index[tag_key][tag_value].add(measurement_m_node)
        else:
            self.tag_index.setdefault(tag_key, {})[tag_value] = set([measurement_m_node])

    def add_index(self, tags_map: dict, measurement_m_node: IMeasurementMNode) -> None:
        if not isinstance(tags_map, dict):
            return
        for tag_key, tag_value in tags_map.items():
            self.add_index(tag_key, tag_value, measurement_m_node)

    def remove_index(self, tag_key: str, tag_value: str, measurement_m_node: IMeasurementMNode) -> None:
        if tag_key not in self.tag_index or tag_value not in self.tag_index[tag_key]:
            return
        self.tag_index[tag_key][tag_value].remove(measurement_m_node)
        if len(self.tag_index[tag_key][tag_value]) == 0:
            del self.tag_index[tag_key][tag_value]
            if len(self.tag_index[tag_key]) == 0:
                del self.tag_index[tag_key]

    def get_matched_timeseries_in_index(self, plan: ShowTimeSeriesPlan, context: QueryContext) -> List[IMeasurementMNode]:
        if not self.tag_index.get(plan.key):
            raise MetadataException("The key " + str(plan.key) + " is not a tag.")
        value2_node = self.tag_index[plan.key]
        matched_nodes = []
        for entry in value2_node.items():
            if plan.is_contains:
                for node in entry.value:
                    if any(tag_value.contains(plan.value) for tag_value in [entry.key]):
                        matched_nodes.append(node)
            else:
                if entry.key == plan.value and len(entry.value) > 0:
                    matched_nodes.extend(list(entry.value))
        return matched_nodes

    def remove_from_tag_inverted_index(self, measurement_m_node: IMeasurementMNode) -> None:
        tag_map = self.tag_log_file.read_tags(measurement_m_node.offset)
        if not isinstance(tag_map, dict):
            return
        for entry in tag_map.items():
            key = entry[0]
            value = entry[1]
            if key in self.tag_index and value in self.tag_index[key]:
                self.logger.debug(self.TAG_FORMAT % (key, value, measurement_m_node.offset))
                self.remove_index(key, value, measurement_m_node)
            else:
                self.logger.debug(self.DEBUG_MSG_1 % ("Delete", key, value, measurement_m_node.offset, self.tag_index.get(key)))
        return

    def update_tags_and_attributes(self, tags_map: dict, attributes_map: dict, leaf_m_node: IMeasurementMNode) -> None:
        pair = self.tag_log_file.read(measurement_m_node.offset)
        if not isinstance(tags_map, dict):
            return
        for entry in tags_map.items():
            key = entry[0]
            value = entry[1]
            before_value = pair.left.get(key)
            pair.left[key] = value
            if before_value and self.tag_index.get(key).get(before_value) is not None:
                self.remove_index(key, before_value, leaf_m_node)

    def add_attributes(self, attributes_map: dict, full_path: PartialPath, measurement_m_node: IMeasurementMNode) -> None:
        pair = self.tag_log_file.read(measurement_m_node.offset)
        if not isinstance(attributes_map, dict):
            return
        for entry in attributes_map.items():
            key = entry[0]
            value = entry[1]
            pair.right[key] = value

    def drop_tags_or_attributes(self, keys_set: set, full_path: PartialPath, measurement_m_node: IMeasurementMNode) -> None:
        delete_tag = {}
        for key in keys_set:
            if self.tag_log_file.read(measurement_m_node.offset)[0].get(key):
                remove_val = self.tag_log_file.read(measurement_m_node.offset)[1].pop(key)
                delete_tag[key] = remove_val
            else:
                logger.warn("TimeSeries [%s] does not have tag/attribute [%s]", full_path, key)

    def set_tags_or_attributes_value(self, alter_map: dict, full_path: PartialPath, measurement_m_node: IMeasurementMNode) -> None:
        pair = self.tag_log_file.read(measurement_m_node.offset)
        old_tag_value = {}
        new_tag_value = {}
        for entry in alter_map.items():
            key = entry[0]
            value = entry[1]
            if pair.left.get(key):
                before_value = pair.left[key]
                new_tag_value[key] = value
                pair.left[key] = value
                self.remove_index(key, before_value, measurement_m_node)
        for old_key in list(old_tag_value.keys()):
            key = old_key
            value = old_tag_value[old_key]
            if not new_tag_value.get(key):
                del old_tag_value[key]

    def rename_tag_or_attribute_key(self, old_key: str, new_key: str, full_path: PartialPath, measurement_m_node: IMeasurementMNode) -> None:
        pair = self.tag_log_file.read(measurement_m_node.offset)
        if not isinstance(pair.left.get(old_key), dict):
            return
        value = pair.left.pop(old_key)
        pair.left[new_key] = value

    def write_tag_file(self, tags: dict, attributes: dict) -> long:
        return self.tag_log_file.write(tags, attributes)

    def read_tag_file(self, tag_file_offset: int) -> Pair[dict, dict]:
        return self.tag_log_file.read(tag_file_offset)
