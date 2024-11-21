class Status:
    LIVE = 0
    OFFLINE = 1
    JOINING = 2
    LEAVING = 3

    def __init__(self):
        pass

    @staticmethod
    def execute(proxy):
        status_map = proxy.get_all_node_status()
        if status_map is None:
            print("BUILDING_CLUSTER_INFO")
            return
        
        print("%-30s   %10s" % ("Node", "Status"))
        for entry in status_map.items():
            node, status_num = entry
            status = ""
            if status_num == Status.LIVE:
                status = "on"
            elif status_num == Status.OFFLINE:
                status = "off"
            elif status_num == Status.JOINING:
                status = "joining"
            else:
                status = "leaving"

            print("%-30s->%10s" % (str(node), status))

if __name__ == "__main__":
    proxy = None  # Replace with your actual proxy object
    status = Status()
    status.execute(proxy)
