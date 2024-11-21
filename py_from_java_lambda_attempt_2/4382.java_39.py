Here is the translation of the Java code into Python:

```Python
class OrganizationNode:
    MAX_SAME_NAME = 10
    
    COMPARATOR = lambda x, y: -y.compareTo(x) if isinstance(y, OrganizationNode) else x.compareTo(y)

    OPEN_FOLDER_GROUP_ICON = None
    CLOSED_FOLDER_GROUP_ICON = None

    def __init__(self, list_of_nodes, max_group_size, monitor):
        self.total_count = len(list_of_nodes)
        
        # organize children further if the list is too big
        organized_list = self.organize(list_of_nodes, max_group_size, monitor)

        # if all the entries have the same name and we have more than a handful, show only 
        # a few and add a special "More" node
        if len(organized_list) > MAX_SAME_NAME and self.has_same_name(organized_list):
            base_name = organized_list[0].name
            organized_list = organized_list[:MAX_SAME_NAME]
            more_node = MoreNode(base_name, self.total_count - MAX_SAME_NAME)
            organized_list.append(more_node)
        else:
            # name this node the prefix that all children nodes have in common
            base_name = self.get_common_prefix(organized_list)

        self.do_set_children(organized_list)

    def organize(self, list_of_nodes, max_group_size, monitor):
        map_of_names_to_lists = self.partition(list_of_nodes, max_group_size, monitor)
        
        # if they didn't partition, just add all given nodes as children
        if map_of_names_to_lists is None:
            return [node for node in list_of_nodes]
        
        # otherwise, the nodes have been partitioned into groups with a common prefix 
        # loop through and create organization nodes for groups larger than one element
        organized_list = []
        for name, group in map_of_names_to_lists.items():
            if not name:
                organized_list.extend(group)
            elif len(group) == 1:
                organized_list.extend(group)
            else:
                organized_list.append(OrganizationNode(group, max_group_size, monitor))

        return organized_list

    def partition(self, list_of_nodes, max_group_size, monitor):
        # no need to partition of the number of nodes is small enough
        if len(list_of_nodes) <= max_group_size:
            return None
        
        common_prefix_size = self.get_common_prefix_size(list_of_nodes)
        unique_prefix_size = common_prefix_size + 1
        map_of_names_to_lists = {}
        
        for node in list_of_nodes:
            monitor.check_cancelled()
            
            prefix = self.get_prefix(node, unique_prefix_size)
            if not name := map_of_names_to_lists.setdefault(prefix, []):
                name.append(node)

        return map_of_names_to_lists

    def get_common_prefix(self, list_of_nodes):
        node = list_of_nodes[0]
        first_name = node.name
        in_common_size = len(first_name)
        
        for i in range(1, len(list_of_nodes)):
            next_node = list_of_nodes[i]
            name = next_node.name
            
            in_common_size = min(in_common_size, self.get_common_prefix_size(first_name, name, in_common_size))
            
        return first_name[:in_common_size]

    def get_common_prefix_size(self, base, candidate, max):
        for i in range(max):
            if base[i] != candidate[i]:
                return i
        return max  # one string is a subset of the other (or the same)

    def has_same_name(self, list_of_nodes):
        if len(list_of_nodes) < 2:
            return False
        
        name = list_of_nodes[0].name
        for node in list_of_nodes:
            if node.name != name:
                return False

        return True

class MoreNode:
    def __init__(self, base_name, count):
        self.base_name = base_name
        self.count = count

    def increment_count(self):
        self.count += 1

    def decrement_count(self):
        self.count -= 1