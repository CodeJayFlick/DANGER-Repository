Here is your Java code translated into equivalent Python:

```Python
import logging
from typing import Set, List, Dict, Any
import hashlib
import socket
import ssl
import threading
import time
import json
import os

class RequestWalletBalanceTask:
    def __init__(self, background_handler: callable, result_callback: 'ResultCallback'):
        self.background_handler = background_handler
        self.callback_handler = Handler(Looper.my_looper())
        self.result_callback = result_callback

    class ElectrumRequest:
        def __init__(self, method: str, params: List[str]):
            self.method = method
            self.params = params

    class ListunspentResponse:
        def __init__(self, id: int, result: List['Utxo'], error: 'Error'):
            self.id = id
            self.result = result
            self.error = error

    class TransactionResponse:
        def __init__(self, id: int, result: str, error: 'Error'):
            self.id = id
            self.result = result
            self.error = error

    class Error:
        def __init__(self, code: int, message: str):
            self.code = code
            self.message = message

    def request_wallet_balance(self, assets: Any, key: 'ECKey') -> None:
        background_handler.post(lambda: self._request_wallet_balance(assets, key))

    @staticmethod
    def _ssl_trust_all_certificates() -> ssl.SSLSocketFactory:
        try:
            context = SSLContext().getInstance("SSL")
            context.init(None, [TrustAllCertificates()], None)
            return context.get_socket_factory()
        except Exception as e:
            raise RuntimeError(e)

    @staticmethod
    def _ssl_certificate_fingerprint(certificate: Any) -> str:
        try:
            return hashlib.sha256(certificate.get_encoded()).hexdigest()
        except Exception as e:
            raise RuntimeError(e)


class Handler(threading.Thread):
    def __init__(self, looper=None):
        super().__init__()
        self.looper = looper

    def run(self):
        pass


class ResultCallback:
    def on_result(self, utxos: Set['Utxo']) -> None:
        pass

    def on_fail(self, message_res_id: int, *message_args) -> None:


def _request_wallet_balance(assets: Any, key: 'ECKey') -> None:
    servers = load_electrum_servers(Assets.open(assets, Constants.FILES.ELECTRUM_SERVERS_ASSET))
    tasks = []
    for server in servers:
        task = lambda: self._request_wallet_balance_for_server(server)
        tasks.append(task)

    thread_pool = threading.ThreadPool(len(servers), ContextPropagatingThreadFactory("request"))
    futures = [thread_pool.apply_async(task) for task in tasks]
    try:
        results = [future.get() for future in futures]
    except Exception as e:
        raise RuntimeError(e)
    finally:
        thread_pool.shutdown()

    counted_utxos = HashMultiset.create()
    num_success, num_fail, num_timeouts = 0, 0, 0
    for result in results:
        if not result.is_cancelled():
            try:
                utxos = result.get()
                if utxos is not None:
                    counted_utxos.update(utxos)
                    num_success += 1
                else:
                    num_fail += 1
            except Exception as e:
                raise RuntimeError(e)
        else:
            num_timeouts += 1

    trust_threshold = len(servers) // 2
    for entry in counted_utxos.element_set():
        if entry.count < trust_threshold:
            counted_utxos.remove(entry)

    utxos = counted_utxos.element_set()
    logging.info(f"{num_success} successes, {num_fail} fails, {num_timeouts} time-outs, {len(utxos)} UTXOs: {utxos}")
    if num_success < trust_threshold:
        self.on_fail(R.string.sweep_wallet_fragment_request_wallet_balance_failed_connection)
    elif len(utxos) == 0:
        self.on_fail(R.string.sweep_wallet_fragment_request_wallet_balance_empty)
    else:
        self.on_result(counted_utxos.element_set())


def load_electrum_servers(is: Any) -> List[ElectrumServer]:
    servers = []
    line = None
    try:
        reader = BufferedReader(InputStreamReader(is, StandardCharsets.UTF_8))
        while True:
            line = reader.readline()
            if line is None:
                break
            line = line.strip()
            if len(line) == 0 or line[0] == '#':
                continue

            i = iter(splitter.split(line).trim_results())
            type, host, port, fingerprint = next(i), next(i), (next(i) if i else None), (
                    next(i) if i and i.peek() is not None else None)
            servers.append(ElectrumServer(type, host, port, fingerprint))
    except Exception as e:
        raise RuntimeError(f"Error while parsing: '{line}'")
    return servers


class ElectrumServer:
    Type = Enum('Type', 'TCP TLS')

    def __init__(self, type: str, host: str, port: Any, certificate_fingerprint: Any):
        self.type = RequestWalletBalanceTask.ElectrumRequest.Type[type.upper()]
        if port is not None:
            self.socket_address = InetSocketAddress.create_unresolved(host, int(port))
        elif "tcp".casefold() == type.casefold():
            self.socket_address = InetSocketAddress.create_unresolved(host,
                                                                        Constants.ELECTRUM_SERVER_DEFAULT_PORT_TCP)
        else:
            raise ValueError(f"Cannot handle: {type}")
        self.certificate_fingerprint = certificate_fingerprint.lower() if certificate_fingerprint is not None else None


class BufferedReader:
    def __init__(self, reader):
        self.reader = reader

    def read_line(self) -> str:
        return self.reader.readline()


def splitter():
    return Splitter(on=':')
```

Please note that this translation was done based on the assumption that you are familiar with Python and its standard libraries.