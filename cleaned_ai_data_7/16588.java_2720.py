class NodeReport:
    def __init__(self, this_node):
        self.this_node = this_node
        self.meta_member_report = None
        self.data_member_reports = []

    def set_meta_member_report(self, meta_member_report):
        self.meta_member_report = meta_member_report

    def set_data_member_reports(self, data_member_reports):
        self.data_member_reports = data_member_reports

    def __str__(self):
        report_str = f"Report of {self.this_node}\n"
        if self.meta_member_report:
            report_str += str(self.meta_member_report) + "\n"
        for report in self.data_member_reports:
            report_str += str(report) + "\n"
        return report_str


class RaftMemberReport:
    def __init__(self, character, leader, term, last_log_term, last_log_index, commit_index, commit_term,
                 is_read_only, last_heartbeat_received_time, prev_last_log_index, max_applied_log_index):
        self.character = character
        self.leader = leader
        self.term = term
        self.last_log_term = last_log_term
        self.last_log_index = last_log_index
        self.commit_index = commit_index
        self.commit_term = commit_term
        self.is_read_only = is_read_only
        self.last_heartbeat_received_time = last_heartbeat_received_time
        self.prev_last_log_index = prev_last_log_index
        self.max_applied_log_index = max_applied_log_index

    def __str__(self):
        return f"RaftMemberReport({self.character}, {self.leader}, {self.term}, {self.last_log_term}, " \
               f"{self.last_log_index}, {self.commit_index}, {self.commit_term}, {self.is_read_only})"


class MetaMemberReport(RaftMemberReport):
    def __init__(self, character, leader, term, last_log_term, last_log_index, commit_index, commit_term,
                 is_read_only, last_heartbeat_received_time, prev_last_log_index, max_applied_log_index):
        super().__init__(character, leader, term, last_log_term, last_log_index, commit_index, commit_term,
                         is_read_only, last_heartbeat_received_time, prev_last_log_index, max_applied_log_index)

    def __str__(self):
        read_bytes = RpcStat.get_read_bytes()
        write_bytes = RpcStat.get_write_bytes()
        compression_ratio = (read_bytes / RpcStat.get_read_compressed_bytes()) if read_bytes else 0
        return f"MetaMemberReport({self.character}, {self.leader}, {self.term}, " \
               f"{self.last_log_term}, {self.last_log_index}, {self.commit_index}, {self.commit_term}, " \
               f"{self.is_read_only}, last_heartbeat={System.currentTimeMillis() - self.last_heartbeat_received_time}ms ago, " \
               f"log_increment={(self.last_log_index - self.prev_last_log_index)}"


class DataMemberReport(RaftMemberReport):
    def __init__(self, character, leader, term, last_log_term, last_log_index, commit_index, commit_term,
                 header, is_read_only, header_latency, last_heartbeat_received_time, prev_last_log_index,
                 max_applied_log_index):
        super().__init__(character, leader, term, last_log_term, last_log_index, commit_index, commit_term,
                         is_read_only, last_heartbeat_received_time, prev_last_log_index, max_applied_log_index)
        self.header = header
        self.header_latency = header_latency

    def __str__(self):
        return f"DataMemberReport({self.character}, {self.leader}, {self.term}, " \
               f"{self.last_log_term}, {self.last_log_index}, {self.commit_index}, {self.commit_term}, " \
               f"{self.is_read_only}, header_latency={self.header_latency}ns, last_heartbeat=" \
               f"{System.currentTimeMillis() - self.last_heartbeat_received_time}ms ago"
