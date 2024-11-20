import base64
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeys
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, DirectoryString

class ApplicationKeyManagerUtils:
    RSA_TYPE = "RSA"
    KEY_SIZE = 4096
    SIGNING_ALGORITHM = "SHA512withRSA"

    BEGIN_CERT = "-----BEGIN CERTIFICATE-----"
    END_CERT = "-----END CERTIFICATE-----"

    @staticmethod
    def get_signed_token(authorities, token):
        try:
            private_key = None
            certificate_chain = None

            for key_manager in ApplicationKeyManagerFactory.get_key_managers():
                if not isinstance(key_manager, x509.KeyManager):
                    continue
                alias = key_manager.choose_client_alias(["RSA"], authorities, None)
                if alias is not None:
                    private_key = key_manager.get_private_key(alias)
                    certificate_chain = key_manager.get_certificate_chain(alias)
                    break

            if private_key is None or certificate_chain is None:
                raise CertificateException("suitable PKI certificate not found")

            algorithm = certificate_chain[0].signature_algorithm_oid
            sig = x509.Signature(private_key, default_backend())
            try:
                sig.update(token.encode('utf-8'))
            except InvalidKeyException as e:
                raise CertificateException("suitable PKI certificate not found", e)
            return SignedToken(token, sig.sign(), certificate_chain, algorithm)

        finally:
            if private_key is not None:
                try:
                    private_key.destroy()
                except DestroyFailedException:
                    pass

    @staticmethod
    def is_my_signature(authorities, token, signature):
        signed_token = ApplicationKeyManagerUtils.get_signed_token(authorities, token)
        return base64.b64encode(signature) == base64.b64encode(signed_token.signature)

    @staticmethod
    def get_trusted_issuers():
        try:
            trust_managers = ApplicationTrustManagerFactory.get_trust_managers()
            if ApplicationTrustManagerFactory.has_cert_error():
                raise CertificateException("failed to load CA certs", ApplicationTrustManagerFactory.cert_error)
            set = set()

            for trust_manager in trust_managers:
                if not isinstance(trust_manager, x509.TrustManager):
                    continue
                x509_trust_manager = x509.TrustManager(trust_manager)

                try:
                    accepted_issuers = x509_trust_manager.get_accepted_issuers()
                    set.update(issuer.subject for issuer in accepted_issuers)
                except CertificateException as e:
                    raise CertificateException("failed to load CA certs", e)

            return list(set)

        except CertificateException as e:
            return None

    @staticmethod
    def validate_client(cert_chain, auth_type):
        try:
            trust_managers = ApplicationTrustManagerFactory.get_trust_managers()
            if ApplicationTrustManagerFactory.has_cert_error():
                raise CertificateException("failed to load CA certs", ApplicationTrustManagerFactory.cert_error)

            for trust_manager in trust_managers:
                if not isinstance(trust_manager, x509.TrustManager):
                    continue
                x509_trust_manager = x509.TrustManager(trust_manager)
                try:
                    x509_trust_manager.check_client_trusted(cert_chain, auth_type)
                    return

                except CertificateException as e:
                    raise CertificateException("failed to load CA certs", e)

            if check_failure is not None:
                raise check_failure
        finally:
            pass

    @staticmethod
    def make_certificate_chain(cert, *ca_certs):
        chain = [cert]
        for ca_cert in ca_certs:
            chain.append(ca_cert)
        return tuple(chain)

    @staticmethod
    def export_x509_certificates(certs, file_out):
        try:
            with open(file_out, 'w') as f:
                writer = PrintWriter(f)
                for cert in certs:
                    if not isinstance(cert, x509.Certificate):
                        continue

                    writer.write(ApplicationKeyManagerUtils.BEGIN_CERT + '\n')
                    base64.b64encode(cert.public_bytes()).decode('utf-8')

        except (IOError, CertificateEncodingException) as e:
            raise

    @staticmethod
    def create_key_store(alias, dn, duration_days, ca_entry=None, key_file=None, keystore_type='JKS', protected_passphrase=b''):
        try:
            password_protection = PasswordProtection(protected_passphrase)
            load_store_parameter = None if not key_file else LoadStoreParameter(password_protection)

            rsa_key_pair_generator = RSAPrivateKeys.generate(KEY_SIZE, default_backend())
            issuer_private_key = rsa_key_pair_generator.private_key

            subject_public_info = x509.SubjectPublicKeyInfo.from_pem(issuer_private_key.public_bytes('DER'))
            ca_x500_name = NameOID.COMMON_NAME if not ca_entry else ca_entry.subject
            key_usage = KeyUsage.digital_signature | KeyUsage.key_encipherment | KeyUsage.certificate_signing

            date_not_before = datetime.now()
            duration_ms = (duration_days * 24 * 60 * 60)
            date_not_after = datetime.fromtimestamp(date_not_before.timestamp() + duration_ms)

            serial_number = Random.get_random_bytes(16).hex()

            certificate_builder = x509.CertificateBuilder(ca_x500_name, serial_number, date_not_before, date_not_after, subject_public_info.public_key, default_backend())
            if ca_entry:
                certificate_builder.add_extension(x509.BasicConstraints(True))
            else:
                certificate_builder.add_extension(x509.SubjectKeyIdentifier.from_pem(issuer_private_key.public_bytes('DER')))

            content_signer = JcaContentSignerBuilder(SIGNING_ALGORITHM).build(issuer_private_key)
            x509_certificate = JcaX509CertificateConverter().get_certificate(certificate_builder.build(content_signer))

            if ca_entry:
                certificate_chain = ApplicationKeyManagerUtils.make_certificate_chain(x509_certificate, *ca_entry.certificate_chain)
            else:
                certificate_chain = [x509_certificate]

            key_store = KeyStore()
            key_store.set_key_entry(alias, issuer_private_key, protected_passphrase, certificate_chain)

            if key_file:
                with open(key_file, 'wb') as f:
                    try:
                        key_store.store(f, password_protection)
                    except SyncFailedException:
                        pass
                os.chmod(key_file, 0o644 | stat.S_IRUSR | stat.S_IWUSR)

        except (GeneralSecurityException, OperatorException) as e:
            raise KeyStoreException("Failed to generate/store certificate", e)

    @staticmethod
    def create_key_entry(alias, dn, duration_days, ca_entry=None, key_file=None, keystore_type='JKS', protected_passphrase=b''):
        try:
            return ApplicationKeyManagerUtils.create_key_store(alias, dn, duration_days, ca_entry, key_file, keystore_type, protected_passphrase)

        except (NoSuchAlgorithmException, UnrecoverableEntryException) as e:
            raise KeyStoreException("Failed to generate/store certificate", e)
