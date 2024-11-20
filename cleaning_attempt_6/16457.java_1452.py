import logging

class MetaLogApplier:
    def __init__(self, member):
        self.member = member
        self.logger = logging.getLogger(__name__)

    def apply(self, log):
        try:
            self.logger.debug("MetaMember [{}] starts applying Log {}".format(member.name, log))
            if isinstance(log, AddNodeLog):
                self.apply_add_node_log(log)
            elif isinstance(log, PhysicalPlanLog):
                self.apply_physical_plan((log.get_plan(), None))
            elif isinstance(log, RemoveNodeLog):
                self.apply_remove_node_log(log)
            elif isinstance(log, EmptyContentLog):
                # Do nothing
                pass
            else:
                self.logger.error("Unsupported log: {} {}".format(log.__class__.__name__, log))
        except Exception as e:
            self.logger.debug("Exception occurred when executing {}: {}".format(log, e), exc_info=True)
            log.set_exception(e)
        finally:
            log.set_applied(True)

    def apply_add_node_log(self, log):
        if not member.get_partition_table().deserialize(log.get_partition_table()):
            self.logger.info("Ignore previous change membership log")
            # ignore previous change membership log
            return
        if member.get_character() == NodeCharacter.LEADER:
            member.get_coordinator().send_log_to_all_data_groups(log)
        member.apply_add_node(log)

    def apply_remove_node_log(self, log):
        if not member.get_partition_table().deserialize(log.get_partition_table()):
            # ignore previous change membership log
            return
        if member.get_character() == NodeCharacter.LEADER:
            member.get_coordinator().send_log_to_all_data_groups(log)
        member.apply_remove_node(log)

class AddNodeLog:
    def __init__(self, partition_table):
        self.partition_table = partition_table

class PhysicalPlanLog:
    def __init__(self, plan):
        self.plan = plan

class RemoveNodeLog:
    def __init__(self, partition_table):
        self.partition_table = partition_table
