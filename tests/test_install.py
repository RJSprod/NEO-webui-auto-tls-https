"""Regression tests for install.py.

install.py runs inside the WebUI's launcher: ``import launch`` and, for anything
missing, ``launch.run_pip``.  These tests put a fake launcher in place, execute
the real file and look at what it asked the launcher to install.

The one rule that matters: a Hypercorn older than the floor is upgraded.  The
old certipie dependency pinned Hypercorn 0.13 into venvs that still carry it,
and an installer that only asked "is some Hypercorn installed?" left that copy
in place, on which HTTP/2 then could not start.

Run with ``python tests/test_install.py`` or ``pytest tests/test_install.py``.
"""

import contextlib
import importlib.metadata
import importlib.util
import io
import os
import sys
import types
import unittest
import unittest.mock

INSTALL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "install.py")


class FakeLaunch:
    """The WebUI's launcher, recording every pip request instead of running it."""

    def __init__(self, installed=()):
        self.module = types.ModuleType("launch")
        self.installed = set(installed)
        self.requests = []
        self.module.run_pip = lambda command, description: self.requests.append((command, description))
        self.module.is_installed = lambda name: name in self.installed


class InstallTestCase(unittest.TestCase):
    def setUp(self):
        self.previous_launch = sys.modules.get("launch")
        self.addCleanup(self.restore_launch)

    def restore_launch(self):
        if self.previous_launch is None:
            sys.modules.pop("launch", None)
        else:
            sys.modules["launch"] = self.previous_launch

    def run_installer(self, hypercorn_version, installed=("certifi",)):
        launch = FakeLaunch(installed)
        sys.modules["launch"] = launch.module
        real_version = importlib.metadata.version

        def version(name):
            if name == "hypercorn":
                if hypercorn_version is None:
                    raise importlib.metadata.PackageNotFoundError(name)
                return hypercorn_version
            return real_version(name)

        spec = importlib.util.spec_from_file_location("autotls_install_under_test", INSTALL)
        module = importlib.util.module_from_spec(spec)
        with unittest.mock.patch("importlib.metadata.version", side_effect=version), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            spec.loader.exec_module(module)
            # Judged while the version is still what the test said it is.
            module.usable_under_test = module.hypercorn_is_usable()
        return launch, module

    def hypercorn_requests(self, launch):
        return [command for command, _ in launch.requests if "hypercorn" in command]

    def test_a_hypercorn_older_than_the_floor_is_upgraded(self):
        launch, _ = self.run_installer("0.13.2")

        requests = self.hypercorn_requests(launch)
        self.assertEqual(len(requests), 1, launch.requests)
        self.assertIn("--upgrade", requests[0])
        self.assertIn("hypercorn>=0.17", requests[0])

    def test_a_missing_hypercorn_is_installed(self):
        launch, _ = self.run_installer(None)

        self.assertEqual(len(self.hypercorn_requests(launch)), 1, launch.requests)

    def test_a_current_hypercorn_is_left_alone(self):
        try:
            import hypercorn  # noqa: F401
        except ImportError:
            self.skipTest("hypercorn is not installed")

        launch, module = self.run_installer("0.18.0")

        self.assertEqual(self.hypercorn_requests(launch), [], launch.requests)
        self.assertTrue(module.usable_under_test)

    def test_the_floor_is_what_the_requirement_says(self):
        _, module = self.run_installer("0.18.0")

        self.assertEqual(module.HYPERCORN_REQUIREMENT, "hypercorn>=" + ".".join(str(p) for p in module.HYPERCORN_MINIMUM))

    def test_a_prerelease_style_version_is_read(self):
        launch, _ = self.run_installer("0.16.0.dev3")

        self.assertEqual(len(self.hypercorn_requests(launch)), 1, launch.requests)


if __name__ == "__main__":
    unittest.main(verbosity=2)
