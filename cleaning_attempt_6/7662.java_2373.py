import socket
import threading
from time import sleep
from logging import getLogger

class BlockStreamServer:
    def __init__(self):
        self.log = getLogger(self.__class__.__name__)
        self.server_socket = None
        self.hostname = None
        self.running = False
        self.block_stream_map = {}
        self.next_stream_id = int(time.time())
        self.cleanup_timer_monitor = None

    @staticmethod
    def get_block_stream_server():
        if not hasattr(BlockStreamServer, 'instance'):
            BlockStreamServer.instance = BlockStreamServer()
        return BlockStreamServer.instance

    def is_running(self):
        return self.running

    def get_server_port(self):
        return self.server_socket.getsockname()[1] if self.server_socket else -1

    def get_server_hostname(self):
        return self.hostname

    def next_stream_id(self):
        id = self.next_stream_id
        self.next_stream_id += 1
        return id

    def register_block_stream(self, stream_handle, block_stream):
        with self.block_stream_map as map:
            if not self.running:
                return False
            if stream_handle is None or block_stream is None:
                raise ValueError("null argument not permitted")
            stream_id = stream_handle.get_stream_id()
            if stream_handle.is_pending() and stream_id in map:
                raise ValueError("stream handle previously registered/used")

            map[stream_id] = BlockStreamRegistration(stream_handle, block_stream)
            return True

    def cleanup_stale_requests(self):
        with self.block_stream_map as map:
            for registration in list(map.values()):
                age = int(time.time()) - registration.timestamp
                if age > 30000:  # MAX_AGE_MS
                    del map[registration.stream_handle.get_stream_id()]
                    try:
                        registration.block_stream.close()
                    except Exception as e:
                        self.log.error("block stream close failed", e)

    def start_server(self, server_socket, host):
        if self.running:
            raise ValueError("server already started")
        if server_socket is None or server_socket.fileno() < 0 or not host:
            raise ValueError("invalid startServer parameters")

        self.server_socket = server_socket
        self.hostname = host
        self.running = True

        self.log.info("Starting Block Stream Server...")
        self.cleanup_timer_monitor = threading.Timer(30000.0, self.cleanup_stale_requests)
        self.cleanup_timer_monitor.start()
        self.run()

    def stop_server(self):
        if not self.running:
            return False
        self.running = False
        try:
            self.server_socket.close()
        except Exception as e:
            pass

class BlockStreamRegistration:
    def __init__(self, stream_handle, block_stream):
        self.stream_handle = stream_handle
        self.block_stream = block_stream
        self.timestamp = int(time.time())
        self.state = HandlerConnectionState.INIT

class BlockStreamHandler(threading.Thread):
    def __init__(self, socket):
        super().__init__()
        self.socket = socket
        self.registration = None

    @staticmethod
    def read_stream_request():
        # Stream request header must be received quickly and processed quickly
        timer_monitor = threading.Timer(10000.0, lambda: self.socket.close())
        try:
            in_socket = self.socket.makefile('rb')
            header_bytes = bytearray(RemoteBlockStreamHandle.HEADER_LENGTH)
            index = 0
            while index < len(header_bytes):
                cnt = in_socket.readinto(header_bytes[index:])
                if cnt <= 0:
                    raise socket.error("connection closed by client")
                index += cnt
        finally:
            timer_monitor.cancel()

        return RemoteBlockStreamHandle.parse_stream_request_header(header_bytes)

    def run(self):
        try:
            stream_request = self.read_stream_request()
            with BlockStreamServer.get_block_stream_server().block_stream_map as map:
                registration = map[stream_request.stream_id]
                if registration is None or not registration.stream_handle.is_pending():
                    self.log.error("unexpected stream connection from " + str(self.socket.getpeername()))
                    return
                if registration.stream_handle.get_authentication_token() != stream_request.authentication_token:
                    self.log.error("unauthorized stream connection from " + str(self.socket.getpeername()))
                    return

            map.pop(stream_request.stream_id)
        except Exception as e:
            self.log.error("stream connection failed", e)

        try:
            if registration.block_stream is not None and isinstance(registration.block_stream, InputBlockStream):
                # ensure input stream is closed since it can be terminated by client,
                # let client handle error if any
                registration.block_stream.close()
        except Exception as e:
            pass

        self.socket.close()

class HandlerConnectionState:
    INIT = 0
    READ_HEADER_TIMEOUT = 1
    CONNECTED = 2
    CLOSED = 3
