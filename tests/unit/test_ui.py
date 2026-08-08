from __future__ import annotations

import importlib.util
import sys
import unittest
from unittest import mock

from log_classification_pipeline.adapters import RulesPredictor
from log_classification_pipeline.ui import build_demo


class GradioUiTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("gradio"), "gradio is not installed")
    def test_build_demo_creates_a_local_blocks_application(self) -> None:
        import gradio

        demo = build_demo(RulesPredictor())
        self.addCleanup(demo.close)

        self.assertIsInstance(demo, gradio.Blocks)
        self.assertEqual(demo.title, "Log Classification Pipeline — alpha")

    def test_missing_optional_dependency_has_a_concise_error(self) -> None:
        with mock.patch.dict(sys.modules, {"gradio": None}):
            with self.assertRaisesRegex(RuntimeError, "UI is optional"):
                build_demo(RulesPredictor())


if __name__ == "__main__":
    unittest.main()
