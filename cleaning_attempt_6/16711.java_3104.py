import unittest
from collections import singleton_list

class ClusterInfoServiceImplTest(unittest.TestCase):
    def setUp(self):
        meta_group_member_test = MetaGroupMemberTest()
        # will create a cluster with 10 nodes, ip: 0,10,20,...100
        meta_group_member_test.setUp()
        meta_group_member = meta_group_member_test.getTestMetaGroupMember()

        meta_cluster_server = MetaClusterServer()
        meta_cluster_server.stop()
        meta_cluster_server.setMetaGroupMember(meta_group_member)

        ClusterMain.setMetaClusterServer(meta_cluster_server)

        meta_cluster_server.getIoTDB().metaManager.setStorageGroup(PartialPath("root", "sg"))
        self.impl = ClusterInfoServiceImpl()

    def tearDown(self):
        cluster_main = ClusterMain()
        storage_groups = singleton_list([PartialPath("root", "sg")])
        cluster_main.getMetaServer().getIoTDB().metaManager.deleteStorageGroups(storage_groups)
        cluster_main.getMetaServer().stop()

    @unittest.skipIf(sys.version_info < (3, 7), "Python version too low")
    def test_get_ring(self):
        nodes = self.impl.getRing()
        self.assertEqual(10, len(nodes))

    def test_data_partition(self):
        entries = self.impl.getDataPartition("root.sg", 0, 100)
        self.assertEqual(1, len(entries))
        nodes = entries[0].getNodes()
        self.assertEqual(50, nodes[0].getNodeIdentifier())
        self.assertEqual(60, nodes[1].getNodeIdentifier())

    def test_get_meta_partition(self):
        nodes = self.impl.getMetaPartition("root.sg")
        self.assertEqual(2, len(nodes))
        self.assertEqual(50, nodes[0].getNodeIdentifier())
        self.assertEqual(60, nodes[1].getNodeIdentifier())

    @unittest.skipIf(sys.version_info < (3, 7), "Python version too low")
    def test_get_instrumenting_info(self):
        # hard to test the content of the instrumentInfo.
        self.assertIsNotNone(self.impl.getInstrumentingInfo())
