import logging
from threading import Thread, Random
from time import sleep
from concurrent.futures import ThreadPoolExecutor

class HeartbeatThread(Thread):
    def __init__(self, local_member):
        self.local_member = local_member
        self.member_name = local_member.name
        self.request = None  # type: HeartBeatRequest
        self.election_request = None  # type: ElectionRequest
        self.random = Random()
        self.has_had_leader = False

    def run(self):
        logging.info("{}: Heartbeat thread starts...".format(self.member_name))
        sleep_time = self.get_election_random_wait_ms()
        try:
            logging.info("{}: Sleep {}ms before first election".format(self.member_name, sleep_time))
            sleep(sleep_time)
        except KeyboardInterrupt as e:
            Thread.currentThread().interrupt()

        while not Thread.currentThread().is_interrupted():
            try:
                if self.local_member.get_character() == NodeCharacter.LEADER:
                    self.send_heartbeats()
                    with self.local_member.heartbeat_wait_object:
                        self.local_member.heartbeat_wait_object.wait(RaftServer.HEARTBEAT_INTERVAL_MS)
                    self.has_had_leader = True
                elif self.local_member.get_character() == NodeCharacter.FOLLOWER:
                    heartbeat_interval = int(time.time()) - self.local_member.last_heartbeat_received_time
                    random_election_timeout = RaftServer.ELECTION_TIMEOUT_MS + self.get_election_random_wait_ms()
                    if heartbeat_interval >= random_election_timeout:
                        logging.info("{}: The leader {} timed out".format(self.member_name, self.local_member.leader))
                        self.local_member.set_character(NodeCharacter.ELECTOR)
                        self.local_member.set_leader(ClusterConstant.EMPTY_NODE)
                    else:
                        logging.debug(" {}: Heartbeat from leader {} is still valid".format(self.member_name, self.local_member.leader))
                        with self.local_member.heartbeat_wait_object:
                            least_wait_time = self.local_member.last_heartbeat_received_time + random_election_timeout - int(time.time())
                            self.local_member.heartbeat_wait_object.wait(least_wait_time)
                    self.has_had_leader = True
                elif self.local_member.get_character() == NodeCharacter.ELECTOR or self.local_member.get_character() is None:
                    self.on_elections_start()
                    self.start_elections()
                    self.on_elections_end()

            except KeyboardInterrupt as e:
                Thread.currentThread().interrupt()
                break

        logging.info("{}: Heartbeat thread exits".format(self.member_name))

    def send_heartbeats(self):
        with self.local_member.term:
            request.set_term(self.local_member.get_term())
            request.set_leader(self.local_member.this_node)
            request.set_commit_log_index(self.local_member.log_manager.commit_log_index)
            request.set_commit_log_term(self.local_member.log_manager.commit_log_term)

            for node in self.local_member.all_nodes:
                if node == self.local_member.this_node:
                    continue
                try:
                    logging.debug("{}: Sending heartbeat to {}".format(self.member_name, node))
                    client = self.local_member.get_async_heartbeat_client(node)
                    if client is not None:
                        client.send_heartbeat(request, HeartbeatHandler(self.local_member, node))

                except Exception as e:
                    logging.warn(" {}: Cannot send heart beat to {} due to network".format(self.member_name, node), e)

    def start_elections(self):
        while self.local_member.get_character() == NodeCharacter.ELECTOR:
            try:
                self.start_election()
                if self.local_member.get_character() == NodeCharacter.ELECTOR:
                    sleep_time = self.get_election_random_wait_ms()
                    logging.info("{}: Sleep {}ms until next election".format(self.member_name, sleep_time))
                    time.sleep(sleep_time)

            except KeyboardInterrupt as e:
                Thread.currentThread().interrupt()

        try:
            self.local_member.term.wait(RaftServer.ELECTION_TIMEOUT_MS)
        except Exception as e:
            pass

    def start_election(self):
        if not self.local_member.is_skip_election():
            with self.local_member.term:
                next_term = self.local_member.get_term() + 1
                self.local_member.set_vote_for(self.local_member.this_node)
                self.local_member.update_hard_state(next_term, self.local_member.vote_for)

                quorum_num = len(self.local_member.all_nodes) // 2

                election_terminated = False
                election_valid = False
                failing_vote_counter = quorum_num + 1

                request.set_term(next_term)
                request.set_elector(self.local_member.this_node)
                request.set_last_log_term(self.local_member.log_manager.last_log_term)
                request.set_last_log_index(self.local_member.log_manager.last_log_index)

                for node in self.local_member.all_nodes:
                    if node == self.local_member.this_node:
                        continue
                    try:
                        logging.info("{}: Requesting a vote from {}".format(self.member_name, node))
                        client = self.local_member.get_async_heartbeat_client(node)
                        if client is not None:
                            client.start_election(request)

                    except Exception as e:
                        logging.error(" {}: Cannot request a vote from {} due to network".format(self.member_name, node), e)

                try:
                    time.sleep(RaftServer.ELECTION_TIMEOUT_MS)
                except KeyboardInterrupt as e:
                    Thread.currentThread().interrupt()

            if election_terminated or not self.local_member.is_skip_election():
                logging.info("{}: Election accepted".format(self.member_name))
                self.local_member.set_character(NodeCharacter.LEADER)
                self.local_member.set_leader(self.local_member.this_node)

    def get_election_random_wait_ms(self):
        return abs(random.randint(0, ClusterConstant.ELECTION_MAX_WAIT_MS))

class HeartbeatHandler:
    def __init__(self, local_member, node):
        self.local_member = local_member
        self.node = node

    def on_complete(self, result):
        pass  # type: (result) -> None

    def on_error(self, e):
        logging.error(" {}: Cannot request a vote from {} due to network".format(self.member_name, self.node), e)

class NodeCharacter:
    LEADER = "LEADER"
    FOLLOWER = "FOLLOWER"
    ELECTOR = "ELECTOR"

RaftServer.HEARTBEAT_INTERVAL_MS = 1000
ClusterConstant.EMPTY_NODE = ""
