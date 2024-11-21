class FlatMeasurementCollector:
    def __init__(self, start_node: 'IMNode', path: 'PartialPath') -> None:
        self.start_node = start_node
        self.path = path
        self.is_measurement_traverser = True

    def process_internal_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        if not node.is_measurement() or idx != len(self.nodes) - 2:
            return False
        
        measurement_m_node = node.as_measurement_m_node()
        
        if measurement_m_node.is_multi_measurement():
            multi_measurement_m_node = measurement_m_node.as_multi_measurement_m_node()
            
            measurements = multi_measurement_m_node.get_sub_measurement_list()
            target_name_regex = self.nodes[idx + 1].replace('*', '.*')
            
            for i in range(len(measurements)):
                if not re.match(target_name_regex, measurements[i]):
                    continue
                
                if self.has_limit:
                    self.cur_offset += 1
                    if self.cur_offset < self.offset:
                        break
                    
                self.collect_multi_measurement_component(multi_measurement_m_node, i)
                
                if self.has_limit:
                    self.count += 1
            
            return True
        
        return False

    def process_full_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        if not node.is_measurement():
            return False
        
        measurement_m_node = node.as_measurement_m_node()
        
        if measurement_m_node.is_unary_measurement():
            if self.has_limit:
                self.cur_offset += 1
                if self.cur_offset < self.offset:
                    return True
            
            self.collect_unary_measurement(measurement_m_node.as_unary_measurement_m_node())
            
            if self.has_limit:
                self.count += 1
        
        elif measurement_m_node.is_multi_measurement():
            if idx >= len(self.nodes) - 1 and not self.nodes[-1].endswith(MULTI_LEVEL_PATH_WILDCARD) and not self.is_prefix_match:
                return True
            
            multi_measurement_m_node = measurement_m_node.as_multi_measurement_m_node()
            
            # only when idx > nodes.length or nodes ends with ** or isPrefixMatch
            measurements = multi_measurement_m_node.get_sub_measurement_list()
            
            for i in range(len(measurements)):
                if self.has_limit:
                    self.cur_offset += 1
                    if self.cur_offset < self.offset:
                        return True
                
                self.collect_multi_measurement_component(multi_measurement_m_node, i)
                
                if self.has_limit:
                    self.count += 1
            
            return True
        
        return True

    def collect_unary_measurement(self, node: 'UnaryMeasurementMNode') -> None:
        # abstract method
        pass

    def collect_multi_measurement_component(self, node: 'MultiMeasurementMNode', index: int) -> None:
        # abstract method
        pass


class IMNode:
    def is_measurement(self):
        return False  # override this in your implementation

    def as_measurement_m_node(self):
        raise NotImplementedError("This should be implemented by the concrete class")

    def get_sub_measurement_list(self):
        raise NotImplementedError("This should be implemented by the concrete class")


class PartialPath:
    pass


re = re.compile
MULTI_LEVEL_PATH_WILDCARD = '*'
