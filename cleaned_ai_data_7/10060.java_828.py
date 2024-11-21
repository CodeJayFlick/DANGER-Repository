class ClientUtil:
    private static _client_authenticator = None
    private static _server_handles = {}

    def __init__(self):
        pass

    @staticmethod
    def set_client_authenticator(authenticator):
        global _client_authenticator
        _client_authenticator = authenticator
        Authenticator.set_default(_client_authenticator.get_authenticator())
        SSHKeyManager.set_protected_key_store_password_provider(_client_authenticator)
        ApplicationKeyManagerFactory.set_key_store_password_provider(_client_authenticator)

    @staticmethod
    def get_client_authenticator():
        if _client_authenticator is None:
            if SystemUtilities.is_in_headless_mode():
                set_client_authenticator(HeadlessClientAuthenticator())
            else:
                set_client_authenticator(DefaultClientAuthenticator())
        return _client_authenticator

    @staticmethod
    def get_repository_server(host, port):
        return get_repository_server(host, port, False)

    @staticmethod
    def get_repository_server(host, port, force_connect=False):
        ensure_default_callback_is_setup()
        host = host.strip().lower()
        try:
            host = InetNameLookup.get_canonical_host_name(host)
        except UnknownHostException as e:
            Msg.warn(ClientUtil, "Failed to resolve hostname for " + host)

        if port <= 0:
            port = GhidraServerHandle.DEFAULT_PORT

        server_info = ServerInfo(host, port)
        adapter = _server_handles.get(server_info)
        if adapter is None:
            adapter = RepositoryServerAdapter(server_info)
            _server_handles[server_info] = adapter
            force_connect = True

        if force_connect:
            try:
                adapter.connect()
            except NotConnectedException as e:
                # message already displayed by RepositoryServerAdapter, so don't handle here
                pass

        return adapter

    @staticmethod
    def clear_repository_adapter(host, port):
        host = host.strip().lower()
        host_addr = host
        try:
            host_addr = InetNameLookup.get_canonical_host_name(host)
        except UnknownHostException as e:
            raise IOException("Repository server lookup failed: " + host)

        if port == 0:
            port = GhidraServerHandle.DEFAULT_PORT

        server_info = ServerInfo(host_addr, port)
        adapter = _server_handles.pop(server_info)
        if adapter is not None:
            adapter.disconnect()

    @staticmethod
    def get_user_name():
        name = SystemUtilities.get_user_name()
        # exclude domain prefix which may be included
        slash_index = name.rfind('\\')
        if slash_index >= 0:
            name = name[slash_index + 1:]
        return name

    @staticmethod
    def handle_exception(repository, exc, operation, must_retry=True, parent=None):
        title = "Error During " + operation
        if isinstance(exc, (ConnectException, NotConnectedException)):
            Msg.debug(ClientUtil, "Server not connected (" + operation + ")")
            prompt_for_reconnect(repository, operation, must_retry, parent)
        elif isinstance(exc, UserAccessException):
            Msg.show_error(ClientUtil, parent, title,
                           "Access denied: " + str(repository) + "\n" + exc.message)
        elif isinstance(exc, (ServerException, ServerError)):
            Msg.show_error(ClientUtil, parent, title,
                           "Exception occurred on the Ghidra Server.", exc.cause())
        else:
            if must_retry:
                msg = "The " + operation + \
                      " may have failed due to a lost connection with the Ghidra Server.\n" \
                      "You may have to retry the operation after you have reconnected to the server."
            else:
                msg = "The connection to the Ghidra Server has been lost."

            Msg.show_error(ClientUtil, parent, title, msg, exc)

    @staticmethod
    def prompt_for_reconnect(repository, operation=None, must_retry=True, parent=None):
        if _client_authenticator is None:
            return

        sb = StringBuffer()
        if must_retry:
            sb.append("The " + operation +
                       " may have failed due to a lost connection with the Ghidra Server.\n" \
                       "You may have to retry the operation after you have reconnected to the server.")
        else:
            sb.append("The connection to the Ghidra Server has been lost.")

        if repository is not None and _client_authenticator.prompt_for_reconnect(parent, sb.toString()):
            try:
                repository.connect()
            except (NotConnectedException, IOException) as e:
                handle_exception(repository, e, "Server Reconnect", parent)

    @staticmethod
    def check_ghidra_server(host, port):
        server_info = ServerInfo(host, port)
        return get_repository_server(server_info).get_handle()

    @staticmethod
    def change_password(parent, repository, server_info):
        if _client_authenticator is None:
            return

        try:
            pwd = _client_authenticator.get_new_password(parent, server_info, repository.user_id)
            if pwd is not None:
                repository.set_password(
                    HashUtilities.sha256_hash(pwd))
                Msg.show_info(ClientUtil,
                               "Password Changed",
                               "Password was changed successfully")
        finally:
            if pwd is not None:
                # Attempt to remove traces of password in memory
                Arrays.fill(pwd, ' ')

    @staticmethod
    def process_password_callbacks(callbacks, server_name, default_user_id, login_error):
        try:
            for callback in callbacks:
                if isinstance(callback, NameCallback):
                    name_cb = callback
                    name_cb.name = default_user_id
                elif isinstance(callback, PasswordCallback):
                    pass_cb = callback
                elif isinstance(callback, ChoiceCallback):
                    choice_cb = callback
                elif isinstance(callback, AnonymousCallback):
                    anonymous_cb = callback

            if pass_cb is None:
                raise IOException(
                    "Unsupported authentication callback: " + callbacks[0].__class__.__name__)

            _client_authenticator.process_password_callbacks("Repository Server Authentication",
                                                              server_name,
                                                              name_cb,
                                                              pass_cb,
                                                              choice_cb,
                                                              anonymous_cb,
                                                              login_error)

        except Exception as e:
            msg = str(e)
            if msg is None:
                msg = str(e)

            raise IOException(msg, e)

    @staticmethod
    def process_signature_callback(server_name, sig_cb):
        try:
            signed_token = ApplicationKeyManagerUtils.get_signed_token(
                sig_cb.recognized_authorities,
                sig_cb.token)
            sig_cb.sign(signed_token.cert_chain, signed_token.signature)
            Msg.info(ClientUtil,
                      "PKI Authenticating to " + server_name +
                      " as user '" + str(signed_token.cert_chain[0].subject_dn) + "'")
        except Exception as e:
            msg = str(e)
            if msg is None:
                msg = str(e)

            raise IOException(msg, e)

    @staticmethod
    def process_ssh_signature_callback(callbacks, server_name, default_user_id):
        name_cb = None
        ssh_cb = None

        for callback in callbacks:
            if isinstance(callback, NameCallback):
                name_cb = callback
                name_cb.name = default_user_id
            elif isinstance(callback, SSHSignatureCallback):
                ssh_cb = callback

        if ssh_cb is None or not _client_authenticator.is_ssh_key_available():
            return False

        if not _client_authenticator.process_ssh_signature_callbacks(server_name,
                                                                      name_cb,
                                                                      ssh_cb):
            return False

        Msg.info(ClientUtil,
                  "SSH Authenticating to " + server_name +
                  " as user '" + default_user_id + "'")
        return True

    @staticmethod
    def is_ssh_key_available():
        return _client_authenticator.is_ssh_key_available()
