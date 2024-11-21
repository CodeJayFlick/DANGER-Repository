import os
import unittest
from aws_sdk_profiles import ProfileFileSystemSetting
from awssdk import S3Client
from botocore.auth import CredentialResolver
from typing import Dict, List

class TestAwsAuthProvider(unittest.TestCase):

    def setUp(self):
        self.config_dir = tempfile.TemporaryDirectory()
        self.aws_credentials_file_path = os.path.join(self.config_dir.name, 'aws.credentials')

    @classmethod
    def tearDownClass(cls):
        cls.config_dir.cleanup()

    def test_aws(self):
        auth_cfg: Dict[str, str] = {
            "nessie_auth_type": "AwsAuthenticationProvider",
            "nessie_region": "eu-central-1"
        }
        self.assertIsNotNone(NessieAuthenticationProvider.from_config(auth_cfg))
        self.assertEqual(NessieAuthenticationProvider.from_config(auth_cfg).get_authentication().get_aws_region(), auth_cfg["nessie_region"])

    def test_from_config(self):
        auth_cfg: Dict[str, str] = {
            "nessie_auth_type": "AwsAuthenticationProvider"
        }
        authentication = NessieAuthenticationProvider.from_config(auth_cfg)
        self.assertEqual(authentication.get_authentication().get_aws_access_key_id(), 'testFromConfig')
        self.assertEqual(authentication.get_authentication().get_aws_secret_access_key(), 'test_secret')

    def test_static_builder(self):
        os.environ['AWS_ACCESS_KEY_ID'] = "testStaticBuilder"
        os.environ['AWS_SECRET_ACCESS_KEY'] = "test_ secret"

        authentication = AwsAuthenticationProvider.create(Region.AWS_GLOBAL)
        self.assertEqual(authentication.get_authentication().get_aws_access_key_id(), 'testStaticBuilder')
        self.assertEqual(authentication.get_authentication().get_aws_secret_access_key(), 'test_ secret')

    def test_from_config_with_profile(self):
        auth_cfg: Dict[str, str] = {
            "nessie_auth_type": "AwsAuthenticationProvider",
            "nessie_region": Region.US_EAST_1,
            "nessie_profile": "test2"
        }
        authentication = NessieAuthenticationProvider.from_config(auth_cfg)
        self.assertEqual(authentication.get_authentication().get_aws_access_key_id(), 'testFromConfigWithProfile')
        self.assertEqual(authentication.get_authentication().get_aws_region(), Region.US_EAST_1)

    def test_static_builder_with_profile(self):
        write_awssdk_credentials_file(self.config_dir.name, "test1", "testStaticBuilderWithProfile")

        authentication = AwsAuthenticationProvider.create(Region.AWS_GLOBAL, 'test1')
        self.assertEqual(authentication.get_authentication().get_aws_access_key_id(), 'testStaticBuilderWithProfile')

    def test_write_awssdk_credentials_file(self):
        credentials_path = os.path.join(self.config_dir.name, "aws.credentials")
        with open(credentials_path, 'w') as f:
            f.write(f"[test1]\n"
                    f"aws_access_key_id={keyId}\n"
                    f"aws_secret_access_key=test_ secret\n"
                    f"aws_session_token=test_ session")

    def test_check_auth(self):
        authentication = NessieAuthenticationProvider.from_config(auth_cfg)
        self.assertIsInstance(authentication, HttpAuthentication)

if __name__ == '__main__':
    unittest.main()
