"""Сверка CoW-таблицы PERF208: results/cow.json, блок в docs/PERF208.md и свежие счётчики CI.

check  — структура results, блок в документе равен таблице из results; с --counters
         ещё и свежие строки PERF208 равны сохранённым значениям.
update — переписать значения в results из --counters и блок в документе.
render — напечатать таблицу.
"""

import argparse
import json
from pathlib import Path
import re
import sys

BEGIN = "<!-- perf208:cow:begin -->"
END = "<!-- perf208:cow:end -->"
ROW = re.compile(r"^PERF208 (\S+) Counts \{(.*)\}\s*$", re.MULTILINE)
FIELD = re.compile(r"(\w+): (\d+)")
SOURCES = ("sdk", "app")


def parse_counts(text):
    """Имя строки PERF208 -> {поле: число}; расходящиеся дубликаты имени отклоняются."""
    rows = {}
    for name, body in ROW.findall(text):
        counts = {key: int(value) for key, value in FIELD.findall(body)}
        if rows.setdefault(name, counts) != counts:
            raise ValueError(f"строка {name} встречается с разными значениями")
    return rows


def load_counters(directory):
    return {
        source: parse_counts((Path(directory) / f"{source}.txt").read_text(encoding="utf-8"))
        for source in SOURCES
    }


def validate(results):
    """Список нарушений структуры results."""
    problems = []
    fields = results.get("fields")
    if not fields or not isinstance(fields, list):
        return ["нет списка fields"]
    seen = set()
    for row in results.get("rows", []):
        row_id = row.get("id", "?")
        if row_id in seen:
            problems.append(f"{row_id}: повторяющийся id")
        seen.add(row_id)
        if row.get("source") not in SOURCES:
            problems.append(f"{row_id}: source должен быть sdk или app")
        for key in ("title", "before_row", "after_row"):
            if not row.get(key):
                problems.append(f"{row_id}: нет {key}")
        for side in ("before", "after"):
            values = row.get(side, {})
            if sorted(values) != sorted(fields):
                problems.append(f"{row_id}: {side} не совпадает с fields")
            elif not all(isinstance(values[field], int) for field in fields):
                problems.append(f"{row_id}: {side} содержит нечисловое значение")
    if not results.get("rows"):
        problems.append("нет строк rows")
    return problems


def render_table(results):
    fields = results["fields"]
    lines = [
        "| Сценарий | " + " | ".join(f"`{field}`" for field in fields) + " |",
        "|---|" + "---:|" * len(fields),
    ]
    for row in results["rows"]:
        cells = [f"{row['before'][field]} → {row['after'][field]}" for field in fields]
        lines.append(f"| {row['title']} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def block_bounds(document):
    if document.count(BEGIN) != 1 or document.count(END) != 1:
        raise ValueError("в документе нужен ровно один блок perf208:cow")
    start = document.index(BEGIN) + len(BEGIN)
    end = document.index(END)
    if end < start:
        raise ValueError("маркер конца блока стоит раньше начала")
    return start, end


def extract_block(document):
    start, end = block_bounds(document)
    return document[start:end].strip("\n")


def replace_block(document, table):
    start, end = block_bounds(document)
    return document[:start] + "\n" + table + "\n" + document[end:]


def fresh_mismatches(results, counters):
    """Расхождения между сохранёнными значениями и свежими строками PERF208."""
    problems = []
    for row in results["rows"]:
        rows = counters[row["source"]]
        for side in ("before", "after"):
            name = row[f"{side}_row"]
            fresh = rows.get(name)
            if fresh is None:
                problems.append(f"{row['id']}: строки {name} нет в {row['source']}.txt")
                continue
            for field in results["fields"]:
                if fresh.get(field) != row[side][field]:
                    problems.append(
                        f"{row['id']} {side} {field}: сохранено {row[side][field]}, "
                        f"свежее значение {fresh.get(field)}"
                    )
    return problems


def check(results, document, counters=None):
    problems = validate(results)
    if problems:
        return problems
    if extract_block(document) != render_table(results):
        problems.append("блок perf208:cow в документе не равен таблице из results")
    if counters is not None:
        problems.extend(fresh_mismatches(results, counters))
    return problems


def refresh(results, counters):
    """Копия results со значениями из свежих строк; KeyError, если строки нет."""
    updated = json.loads(json.dumps(results))
    for row in updated["rows"]:
        rows = counters[row["source"]]
        for side in ("before", "after"):
            fresh = rows[row[f"{side}_row"]]
            row[side] = {field: fresh[field] for field in updated["fields"]}
    return updated


def dump(results):
    return json.dumps(results, indent=2, ensure_ascii=False) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("command", choices=("check", "update", "render"))
    parser.add_argument("--results", type=Path, default=Path("docs/perf208/results/cow.json"))
    parser.add_argument("--doc", type=Path, default=Path("docs/PERF208.md"))
    parser.add_argument("--counters", type=Path, help="каталог с sdk.txt и app.txt")
    args = parser.parse_args(argv)

    results = json.loads(args.results.read_text(encoding="utf-8"))
    if args.command == "render":
        print(render_table(results))
        return 0
    counters = load_counters(args.counters) if args.counters else None
    if args.command == "update":
        if counters is None:
            parser.error("update требует --counters")
        results = refresh(results, counters)
        args.results.write_text(dump(results), encoding="utf-8")
        document = args.doc.read_text(encoding="utf-8")
        args.doc.write_text(replace_block(document, render_table(results)), encoding="utf-8")
        return 0
    problems = check(results, args.doc.read_text(encoding="utf-8"), counters)
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
