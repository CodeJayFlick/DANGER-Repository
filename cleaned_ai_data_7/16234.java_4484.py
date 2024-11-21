import os
import io
from hdfs3 import InsecureClient as HDFS
from pyzipper import ZIPFile
import json
import unittest
from tempfile import mkdtemp

class TestHdfsRepository(unittest.TestCase):

    def setUp(self):
        self.mini_dfs = None
        if 'os.name' in os.environ and os.environ['os.name'].startswith('Windows'):
            raise SkipTest("MiniDFSCluster doesn't support Windows.")
        
        user_home = os.path.expanduser('~')
        cache_dir = mkdtemp()
        os.putenv('DJL_CACHE_DIR', cache_dir)
        os.putenv('ENGINE_CACHE_DIR', f"{user_home}/.djl.ai")

    def tearDown(self):
        if self.mini_dfs:
            self.mini_dfs.shutdown()

    @unittest.skipIf(os.name.startswith('Windows'), "MiniDFSCluster doesn't support Windows.")
    def test_zip_file(self):
        port = 50010
        with HDFS(f"hdfs://localhost:{port}/mlp.zip", user='root', password='') as fs:
            repo = Repository("hdfs", f"hdfs://localhost:{port}/mlp.zip")
            list_resources = repo.get_resources()
            self.assertFalse(list_resources.empty)

    @unittest.skipIf(os.name.startswith('Windows'), "MiniDFSCluster doesn't support Windows.")
    def test_dir(self):
        port = 50010
        with HDFS(f"hdfs://localhost:{port}/mlp", user='root', password='') as fs:
            repo = Repository("hdfs", f"hdfs://localhost:{port}/mlp")
            list_resources = repo.get_resources()
            self.assertFalse(list_resources.empty)

    @unittest.skipIf(os.name.startswith('Windows'), "MiniDFSCluster doesn't support Windows.")
    def test_access_deny(self):
        port = 50010
        with HDFS(f"hdfs://localhost:{port}/non-exists", user='root', password='') as fs:
            repo = Repository("hdfs", f"hdfs://localhost:{port}/non-exists")
            list_resources = repo.get_resources()
            self.assertTrue(list_resources.empty)

    def set_file_permission(self):
        try:
            process = subprocess.run(["umask"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            umask_bits = int(process.stdout.decode().strip(), 8)
            perm_bits = 0o777 & ~umask_bits
            perms = oct(perm_bits)[2:]
            os.environ['dfs.datanode.data.dir.perm'] = perms
        except (subprocess.CalledProcessError, ValueError):
            pass

if __name__ == '__main__':
    unittest.main()
