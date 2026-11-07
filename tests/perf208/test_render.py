"""Проверки render.py без запуска измерений."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).parent
ROOT = HERE.parent.parent
spec = importlib.util.spec_from_file_location("perf208_render", HERE / "render.py")
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)


def counts_line(name, **values):
    base = {"alloc": 0, "realloc": 0, "requested_bytes": 0, "config_clones": 0, "sort_comparisons": 0}
    base.update(values)
    body = ", ".join(f"{key}: {value}" for key, value in base.items())
    return f"PERF208 {name} Counts {{ {body}, chain_builds: 9 }}"


def sample_results():
    return {
        "stage": "cow",
        "fields": ["alloc", "requested_bytes"],
        "rows": [
            {
                "id": "key",
                "source": "sdk",
                "title": "route key",
                "before_row": "key/legacy",
                "after_row": "key/new",
                "before": {"alloc": 5, "requested_bytes": 271},
                "after": {"alloc": 0, "requested_bytes": 0},
            },
            {
                "id": "tunnel",
                "source": "app",
                "title": "tunnel counters",
                "before_row": "tunnel/legacy",
                "after_row": "tunnel/new",
                "before": {"alloc": 3, "requested_bytes": 72},
                "after": {"alloc": 1, "requested_bytes": 40},
            },
        ],
    }


def sample_counters():
    sdk = "\n".join(
        [
            "test a ... ok",
            counts_line("key/legacy", alloc=5, requested_bytes=271),
            counts_line("key/new"),
        ]
    )
    app = "\n".join(
        [
            counts_line("tunnel/legacy", alloc=3, requested_bytes=72),
            counts_line("tunnel/new", alloc=1, requested_bytes=40),
        ]
    )
    return {"sdk": render.parse_counts(sdk), "app": render.parse_counts(app)}


def sample_document(results):
    return f"intro\n\n{render.BEGIN}\n{render.render_table(results)}\n{render.END}\n\noutro\n"


class ParseTests(unittest.TestCase):
    def test_rows_are_parsed_and_other_lines_ignored(self):
        text = "noise\n" + counts_line("a/b", alloc=2) + "\nok\n"
        rows = render.parse_counts(text)
        self.assertEqual(list(rows), ["a/b"])
        self.assertEqual(rows["a/b"]["alloc"], 2)
        self.assertEqual(rows["a/b"]["chain_builds"], 9)

    def test_identical_duplicates_are_accepted_conflicting_are_not(self):
        same = counts_line("x", alloc=1)
        self.assertEqual(render.parse_counts(same + "\n" + same)["x"]["alloc"], 1)
        with self.assertRaises(ValueError):
            render.parse_counts(same + "\n" + counts_line("x", alloc=2))

    def test_load_counters_reads_both_sources(self):
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            Path(directory, "sdk.txt").write_text(counts_line("s", alloc=1), encoding="utf-8")
            Path(directory, "app.txt").write_text(counts_line("a", alloc=2), encoding="utf-8")
            loaded = render.load_counters(directory)
        self.assertEqual(loaded["sdk"]["s"]["alloc"], 1)
        self.assertEqual(loaded["app"]["a"]["alloc"], 2)


class ValidateTests(unittest.TestCase):
    def test_sample_is_valid(self):
        self.assertEqual(render.validate(sample_results()), [])

    def test_each_structural_defect_is_reported(self):
        cases = {
            "fields": lambda r: r.pop("fields"),
            "rows": lambda r: r.update(rows=[]),
            "source": lambda r: r["rows"][0].update(source="other"),
            "title": lambda r: r["rows"][0].update(title=""),
            "before": lambda r: r["rows"][0]["before"].pop("alloc"),
            "numeric": lambda r: r["rows"][0]["after"].update(alloc="0"),
            "duplicate": lambda r: r["rows"][1].update(id="key"),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                results = sample_results()
                mutate(results)
                self.assertTrue(render.validate(results), name)


class TableTests(unittest.TestCase):
    def test_table_shape(self):
        table = render.render_table(sample_results()).split("\n")
        self.assertEqual(table[0], "| Сценарий | `alloc` | `requested_bytes` |")
        self.assertEqual(table[1], "|---|---:|---:|")
        self.assertEqual(table[2], "| route key | 5 → 0 | 271 → 0 |")
        self.assertEqual(table[3], "| tunnel counters | 3 → 1 | 72 → 40 |")

    def test_block_roundtrip_and_replacement(self):
        results = sample_results()
        document = sample_document(results)
        self.assertEqual(render.extract_block(document), render.render_table(results))
        results["rows"][0]["after"]["alloc"] = 7
        replaced = render.replace_block(document, render.render_table(results))
        self.assertEqual(render.extract_block(replaced), render.render_table(results))
        self.assertTrue(replaced.startswith("intro\n"))
        self.assertTrue(replaced.endswith("outro\n"))

    def test_missing_or_duplicated_markers_are_rejected(self):
        for document in ["no markers", sample_document(sample_results()) * 2, f"{render.END}\n{render.BEGIN}"]:
            with self.subTest(document[:20]):
                with self.assertRaises(ValueError):
                    render.extract_block(document)


class CheckTests(unittest.TestCase):
    def test_consistent_inputs_pass(self):
        results = sample_results()
        self.assertEqual(render.check(results, sample_document(results), sample_counters()), [])
        self.assertEqual(render.check(results, sample_document(results)), [])

    def test_stale_document_is_reported(self):
        results = sample_results()
        document = sample_document(results)
        results["rows"][0]["after"]["alloc"] = 1
        self.assertTrue(render.check(results, document))

    def test_changed_counter_is_reported(self):
        results = sample_results()
        counters = sample_counters()
        counters["sdk"]["key/new"]["alloc"] = 4
        problems = render.check(results, sample_document(results), counters)
        self.assertEqual(len(problems), 1)
        self.assertIn("key after alloc", problems[0])

    def test_missing_counter_row_is_reported(self):
        results = sample_results()
        counters = sample_counters()
        del counters["app"]["tunnel/legacy"]
        problems = render.check(results, sample_document(results), counters)
        self.assertEqual(len(problems), 1)
        self.assertIn("tunnel/legacy", problems[0])

    def test_invalid_results_stop_before_comparison(self):
        results = sample_results()
        results["rows"][0]["source"] = "other"
        self.assertTrue(render.check(results, "no markers", sample_counters()))

    def test_refresh_takes_fresh_values_without_touching_the_input(self):
        results = sample_results()
        original = copy.deepcopy(results)
        counters = sample_counters()
        counters["sdk"]["key/new"]["alloc"] = 3
        updated = render.refresh(results, counters)
        self.assertEqual(updated["rows"][0]["after"]["alloc"], 3)
        self.assertEqual(results, original)
        self.assertEqual(render.fresh_mismatches(updated, counters), [])

    def test_refresh_requires_every_row(self):
        counters = sample_counters()
        del counters["sdk"]["key/new"]
        with self.assertRaises(KeyError):
            render.refresh(sample_results(), counters)


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=HERE)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.results = sample_results()
        (self.root / "cow.json").write_text(render.dump(self.results), encoding="utf-8")
        (self.root / "doc.md").write_text(sample_document(self.results), encoding="utf-8")
        (self.root / "sdk.txt").write_text(
            counts_line("key/legacy", alloc=5, requested_bytes=271) + "\n" + counts_line("key/new", alloc=2),
            encoding="utf-8",
        )
        (self.root / "app.txt").write_text(
            counts_line("tunnel/legacy", alloc=3, requested_bytes=72)
            + "\n"
            + counts_line("tunnel/new", alloc=1, requested_bytes=40),
            encoding="utf-8",
        )

    def run_main(self, command, *extra):
        return render.main(
            [command, "--results", str(self.root / "cow.json"), "--doc", str(self.root / "doc.md"), *extra]
        )

    def test_check_fails_on_counter_drift_and_update_repairs_it(self):
        counters = ["--counters", str(self.root)]
        self.assertEqual(self.run_main("check"), 0)
        self.assertEqual(self.run_main("check", *counters), 1)
        self.assertEqual(self.run_main("update", *counters), 0)
        self.assertEqual(self.run_main("check", *counters), 0)
        updated = json.loads((self.root / "cow.json").read_text(encoding="utf-8"))
        self.assertEqual(updated["rows"][0]["after"]["alloc"], 2)
        self.assertIn("5 → 2", (self.root / "doc.md").read_text(encoding="utf-8"))

    def test_update_without_counters_is_a_usage_error(self):
        with self.assertRaises(SystemExit):
            self.run_main("update")


class RepositoryFilesTests(unittest.TestCase):
    """Закоммиченные results и PERF208.md согласованы между собой."""

    def setUp(self):
        self.path = ROOT / "docs" / "perf208" / "baseline" / "cow.json"
        self.text = self.path.read_text(encoding="utf-8")
        self.results = json.loads(self.text)

    def test_results_are_valid_and_stored_in_canonical_form(self):
        self.assertEqual(render.validate(self.results), [])
        self.assertEqual(render.dump(self.results), self.text)

    def test_document_block_matches_results(self):
        document = (ROOT / "docs" / "PERF208.md").read_text(encoding="utf-8")
        self.assertEqual(render.check(self.results, document), [])

    def test_every_row_improves_or_keeps_each_counter(self):
        for row in self.results["rows"]:
            for field in self.results["fields"]:
                with self.subTest(row["id"], field=field):
                    self.assertLessEqual(row["after"][field], row["before"][field])


if __name__ == "__main__":
    unittest.main()
