Here is the translation of the Java code to Python:

```Python
import threading
from unittest import TestCase
import time
import logging

class AppendNodeEntryHandlerTest(TestCase):

    def setUp(self):
        self.member = TestMetaGroupMember()

    def tearDown(self):
        self.member.close_log_manager()
        self.member.stop()
        EnvironmentUtils.clean_all_dir()

    def test_agreement(self):
        receiver_term = threading.Value('i', -1)
        leadership_stale = threading.Value('b', False)
        log = logging.getLogger(__name__)

        replication_num = ClusterDescriptor().get_config().get_replication_num()
        try:
            ClusterDescriptor().get_config().set_replication_num(10)

            quorum = 5
            peer = Peer(1)

            for i in range(10):
                handler = AppendNodeEntryHandler()
                handler.set_leader_ship_stale(leadership_stale)
                handler.set_vote_counter(quorum)
                handler.set_log(log)
                handler.set_member(self.member)
                handler.set_receiver_term(receiver_term)
                handler.set_receiver(TestUtils.get_node(i))
                handler.set_peer(peer)

                if i >= 5:
                    response = Response.RESPONSE_AGREE
                else:
                    response = Response.RESPONSE_LOG_MISMATCH

                threading.Thread(target=handler.on_complete, args=(response,)).start()

            time.sleep(1)
        finally:
            ClusterDescriptor().get_config().set_replication_num(replication_num)

    def test_no_agreement(self):
        receiver_term = threading.Value('i', -1)
        leadership_stale = threading.Value('b', False)
        log = logging.getLogger(__name__)
        quorum = 5
        peer = Peer(1)

        for i in range(3):
            handler = AppendNodeEntryHandler()
            handler.set_leader_ship_stale(leadership_stale)
            handler.set_vote_counter(quorum)
            handler.set_log(log)
            handler.set_member(self.member)
            handler.set_receiver_term(receiver_term)
            handler.set_receiver(TestUtils.get_node(i))
            handler.set_peer(peer)

            response = Response.RESPONSE_AGREE
            threading.Thread(target=handler.on_complete, args=(response,)).start()

        time.sleep(1)

    def test_leadership_stale(self):
        receiver_term = threading.Value('i', -1)
        leadership_stale = threading.Value('b', False)
        log = logging.getLogger(__name__)
        quorum = 5
        peer = Peer(1)

        handler = AppendNodeEntryHandler()
        handler.set_leader_ship_stale(leadership_stale)
        handler.set_vote_counter(quorum)
        handler.set_log(log)
        handler.set_member(self.member)
        handler.set_receiver_term(receiver_term)
        handler.set_receiver(TestUtils.get_node(0))
        handler.set_peer(peer)

        response = 100
        threading.Thread(target=handler.on_complete, args=(response,)).start()
        time.sleep(1)

    def test_error(self):
        receiver_term = threading.Value('i', -1)
        leadership_stale = threading.Value('b', False)
        log = logging.getLogger(__name__)
        replication_num = ClusterDescriptor().get_config().get_replication_num()

        try:
            quorum = 5
            peer = Peer(1)

            handler = AppendNodeEntryHandler()
            handler.set_leader_ship_stale(leadership_stale)
            handler.set_vote_counter(quorum)
            handler.set_log(log)
            handler.set_member(self.member)
            handler.set_receiver_term(receiver_term)
            handler.set_receiver(TestUtils.get_node(0))
            handler.set_peer(peer)

            response = 100
            threading.Thread(target=handler.on_error, args=(TestException(),)).start()

        finally:
            ClusterDescriptor().get_config().set_replication_num(replication_num)


class TestMetaGroupMember:

    def close_log_manager(self):
        pass

    def stop(self):
        pass


class EnvironmentUtils:

    @staticmethod
    def clean_all_dir():
        pass


class Peer:

    def __init__(self, node_id):
        self.node_id = node_id


class Response:
    RESPONSE_AGREE = 0
    RESPONSE_LOG_MISMATCH = 1

class TestException(Exception):

    pass