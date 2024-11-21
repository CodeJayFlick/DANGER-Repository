import unittest
from djl.engine import Engine
from djl.device import Device

class TestDevice(unittest.TestCase):

    def test_device(self):
        self.assertEqual(Device.cpu(), "cpu")
        engine = Engine.getInstance()
        if engine.getGpuCount() > 0:
            self.assertEqual(Device.gpu(), engine.getDefaultDevice())
        else:
            self.assertEqual(Device.cpu(), engine.getDefaultDevice())

        self.assertEqual(Device.gpu(0), "gpu:0")

        with self.assertRaises(ValueError):
            Device.gpu(-1)

        self.assertNotEqual(Device.cpu(), Device.gpu(0))

        device = Device("myDevice", 1)
        self.assertEqual(device.getDeviceType(), "myDevice")
        
if __name__ == '__main__':
    unittest.main()
