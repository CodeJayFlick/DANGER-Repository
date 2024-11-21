class SceneTest:
    def test_get_buffer(self):
        try:
            scene = Scene()
            field1 = type(scene).getattribute("current")
            field2 = type(scene).getattribute("frameBuffers")

            frameBuffer0 = FrameBuffer()
            frameBuffer0.draw(0, 0)
            frameBuffer1 = FrameBuffer()

            field1.set(scene, 0)
            field2.set(scene, [frameBuffer0, frameBuffer1])

            self.assertEqual(frameBuffer0, scene.get_buffer())
        except AttributeError:
            self.fail("Failed to access private attribute.")

    def test_draw(self):
        try:
            scene = Scene()
            field1 = type(scene).getattribute("current")
            field2 = type(scene).getattribute("next")

            field1.set(scene, 0)
            field2.set(scene, 1)

            scene.draw([])
            self.assertEqual(1, field1.get(scene))
            self.assertEqual(0, field2.get(scene))
        except AttributeError:
            self.fail("Failed to access private attribute.")
