Here is the translation of the given Java code into equivalent Python:

```Python
import logging
from thrift import TException
from thrift.protocol import TProtocol
from thrift.transport import TTransport
from thrift.server import TServer
from thrift.Thrift import Thrift

class BaseSyncService:
    def __init__(self, member):
        self.member = member
        self.name = member.get_name()

    def send_heartbeat(self, request):
        return self.member.process_heartbeat_request(request)

    def start_election(self, request):
        return self.member.process_election_request(request)

    def append_entry(self, request):
        try:
            return self.member.append_entry(request)
        except UnknownLogTypeException as e:
            raise TException(e)

    def append_entries(self, request):
        try:
            return self.member.append_entries(request)
        except BufferUnderflowException as e:
            logging.error("Underflow buffers {} of logs from {}".format(
                request.get_entries(), request.get_prev_log_index() + 1))
            raise TException(e)
        except Exception as e:
            raise TException(e)

    def request_commit_index(self, header):
        commit_index = self.member.get_log_manager().get_commit_log_index()
        commit_term = self.member.get_log_manager().get_commit_log_term()
        cur_term = self.member.get_term()

        response = RequestCommitIndexResponse(cur_term, commit_index, commit_term)
        if commit_index != long.min_value:
            return response

        self.member.wait_leader()
        client = self.member.get_sync_client(self.member.get_leader())
        if client is None:
            raise TException(LeaderUnknownException(self.member.get_all_nodes()))
        try:
            response = client.request_commit_index(header)
        except TException as e:
            client.input_protocol().get_transport().close()
            raise e
        finally:
            ClientUtils.put_back_sync_client(client)

        return response

    def read_file(self, file_path, offset, length):
        try:
            return IOUtils.read_file(file_path, offset, length)
        except IOException as e:
            raise TException(e)

    def remove_hard_link(self, hard_link_path):
        try:
            Files.deleteIfExists(Path(hard_link_path).to_real_path())
        except IOException as e:
            raise TException(e)

    def match_term(self, index, term, header):
        return self.member.match_log(index, term)

    def execute_non_query_plan(self, request):
        if self.member.get_character() != NodeCharacter.LEADER:
            # forward the plan to the leader
            client = self.member.get_sync_client(self.member.get_leader())
            if client is not None:
                status = TSStatus()
                try:
                    status = client.execute_non_query_plan(request)
                except TException as e:
                    client.input_protocol().get_transport().close()
                    raise e
                finally:
                    ClientUtils.put_back_sync_client(client)

                return status

        try:
            return self.member.execute_non_query_plan(request)
        except Exception as e:
            raise TException(e)


class RequestCommitIndexResponse:
    def __init__(self, cur_term, commit_index, commit_term):
        self.cur_term = cur_term
        self.commit_index = commit_index
        self.commit_term = commit_term

    @property
    def cur_term(self):
        return self._cur_term

    @cur_term.setter
    def cur_term(self, value):
        self._cur_term = value

    @property
    def commit_index(self):
        return self._commit_index

    @commit_index.setter
    def commit_index(self, value):
        self._commit_index = value

    @property
    def commit_term(self):
        return self._commit_term

    @commit_term.setter
    def commit_term(self, value):
        self._commit_term = value


class TSStatus:
    pass