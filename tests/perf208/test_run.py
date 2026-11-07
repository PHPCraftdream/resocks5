"""Проверки deadline runner без задержек и запуска дочерних процессов."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location("perf208_run", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "output.txt"

    def process(self, text, returncode=0):
        process = Mock()
        process.communicate.return_value = (text.encode(), None)
        process.returncode = returncode
        return process

    def test_remaining_budget_is_not_restarted(self):
        process = self.process("test result: ok. 1 passed; 0 failed; 0 ignored;\n")
        with patch.object(runner.subprocess, "Popen", return_value=process), patch.object(
            runner.time, "monotonic", return_value=12.0
        ):
            runner.run(Path("unused"), "perf208_", 15.0, self.output)
        process.communicate.assert_called_once_with(timeout=3.0)
        process.kill.assert_not_called()

    def test_timeout_kills_only_owned_process_and_keeps_partial_output(self):
        process = self.process("")
        process.communicate.side_effect = [
            subprocess.TimeoutExpired("owned-test", 3.0),
            (b"partial\n", None),
        ]
        with patch.object(runner.subprocess, "Popen", return_value=process), patch.object(
            runner.time, "monotonic", return_value=12.0
        ):
            with self.assertRaises(TimeoutError):
                runner.run(Path("unused"), "perf208_", 15.0, self.output)
        process.kill.assert_called_once_with()
        self.assertEqual(self.output.read_bytes(), b"partial\n")

    def test_empty_and_failing_runs_are_rejected(self):
        for count, returncode in [(0, 0), (1, 1)]:
            process = self.process(
                f"test result: ok. {count} passed; 0 failed; 0 ignored;\n", returncode
            )
            with patch.object(runner.subprocess, "Popen", return_value=process), patch.object(
                runner.time, "monotonic", return_value=1.0
            ):
                with self.assertRaises(RuntimeError):
                    runner.run(Path("unused"), "perf208_", 15.0, self.output)

    def test_expired_budget_does_not_start_a_process(self):
        with patch.object(runner.subprocess, "Popen") as popen, patch.object(
            runner.time, "monotonic", return_value=16.0
        ):
            with self.assertRaises(TimeoutError):
                runner.run(Path("unused"), "perf208_", 15.0, self.output)
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
