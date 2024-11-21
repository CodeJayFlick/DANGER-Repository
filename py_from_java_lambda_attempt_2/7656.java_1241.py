Here is the translation of the Java code into Python:

```Python
import logging
from ghidra.framework.remote import GhidraPrincipal
from ghidra.server.repository_manager import RepositoryManager
from ghidra.server.user_manager import UserManager
from java.security.cert import X509Certificate, CertificateException
from java.io import IOException

class PKIAuthenticationModule:
    def __init__(self, anonymous_allowed):
        self.anonymous_allowed = anonymous_allowed
        try:
            self.authorities = ApplicationKeyManagerUtils.get_trusted_issuers()
        except (IOException, CertificateException) as e:
            raise Exception("trusted PKI Certificate Authorities have not been configured") from e

    def is_name_callback_allowed(self):
        return False

    def get_authentication_callbacks(self):
        try:
            token = TokenGenerator.get_new_token(TOKEN_SIZE)
            using_self_signed_cert = ApplicationKeyManagerFactory.using_generated_self_signed_certificate()
            signed_token = ApplicationKeyManagerUtils.get_signed_token(using_self_signed_cert, token)
            sig_cb = SignatureCallback(self.authorities, token, signed_token.signature)
        except Exception as e:
            raise RuntimeError("Unable to generate signed token") from e
        return [sig_cb]

    def authenticate(self, user_mgr, subject, callbacks):
        try:
            ghidra_principal = GhidraPrincipal.get_ghidra_principal(subject)
            if ghidra_principal is None:
                raise FailedLoginException("GhidraPrincipal required")
            username = ghidra_principal.name

            sig_cb = None
            for callback in callbacks:
                if isinstance(callback, SignatureCallback):
                    sig_cb = callback
                    break

            if sig_cb is None:
                raise FailedLoginException("PKI Signature callback required")

            token = sig_cb.token
            if not TokenGenerator.is_recent_token(token, MAX_TOKEN_TIME):
                raise FailedLoginException("Stale Signature callback")

            using_self_signed_cert = ApplicationKeyManagerFactory.using_generated_self_signed_certificate()
            if not ApplicationKeyManagerUtils.is_my_signature(using_self_signed_cert, self.authorities, token, sig_cb.server_signature):
                raise FailedLoginException("Invalid Signature callback")

            cert_chain = sig_cb.certificate_chain
            if cert_chain is None or len(cert_chain) == 0:
                raise FailedLoginException("user certificate not provided")

            ApplicationKeyManagerUtils.validate_client(cert_chain, RSA_TYPE)

            signature_bytes = sig_cb.signature
            if signature_bytes is not None:
                try:
                    sig = Signature.getInstance(cert_chain[0].sig_alg_name)
                    sig.init_verify(cert_chain[0])
                    sig.update(token)
                    if not sig.verify(signature_bytes):
                        raise FailedLoginException("Incorrect signature")
                except Exception as e:
                    raise FailedLoginException(str(e))

            dn_username = user_mgr.get_user_by_distinguished_name(cert_chain[0].subject_x500_principal)
            if dn_username is not None:
                return dn_username

            if user_mgr.is_valid_user(username):
                x500_user = user_mgr.get_distinguished_name(username)
                if x500_user is None:
                    user_mgr.log_unknown_dn(username, cert_chain[0].subject_x500_principal)
                    if not self.anonymous_allowed:
                        raise FailedLoginException("Distinguished name is unknown")
                    logging.warning(f"Know user's DN not found ({username})")
                    username = UserManager.ANONYMOUS_USERNAME
                else:
                    # if not cert_chain[0].get_subject_x500_principal().equals(dn.as_x500_principal()):
                    user_mgr.log_unknown_dn(username, cert_chain[0].subject_x500_principal)
                    if not self.anonymous_allowed:
                        raise FailedLoginException(f"Expected distinguished name: {x500_user.name}")
                    username = UserManager.ANONYMOUS_USERNAME
            else:
                if not self.anonymous_allowed:
                    raise FailedLoginException(f"Unknown user: {username}")

            if UserManager.ANONYMOUS_USERNAME == username:
                RepositoryManager.log(None, None, f"Anonymous access allowed for: {cert_chain[0].subject_x500_principal}", ghidra_principal.name)

        except LoginException as e:
            raise e
        except Exception as e:
            msg = str(e)
            if not msg:
                msg = str(e.__class__)
            raise FailedLoginException(msg) from e

        return username


class SignatureCallback:
    def __init__(self, authorities, token, signature):
        self.authorities = authorities
        self.token = token
        self.signature = signature
        self.server_signature = None
        self.certificate_chain = None

    @property
    def server_signature(self):
        return self._server_signature

    @server_signature.setter
    def server_signature(self, value):
        self._server_signature = value


class FailedLoginException(Exception):
    pass
```

Please note that this translation is not perfect and some parts of the code might be missing or incorrect. The original Java code has many dependencies on other classes and methods which are not present in Python.