"""Выполнить уже собранные счётчики #208 в общем бюджете 15 секунд."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time


BUDGET_SECONDS = 15.0
EXPECTED_ROWS = {"sdk": 209, "app": 24}


def executable(manifest):
    candidates = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        message = json.loads(line)
        if (
            message.get("reason") == "compiler-artifact"
            and message.get("profile", {}).get("test")
            and message.get("executable")
        ):
            candidates.add(message["executable"])
    if len(candidates) != 1:
        raise ValueError(f"{manifest.name}: ожидался ровно один test executable")
    binary = Path(candidates.pop()).resolve(strict=True)
    if not binary.is_relative_to(Path.cwd().resolve()):
        raise ValueError("Test executable должен находиться внутри репозитория")
    return binary


def run(binary, test_filter, deadline, output):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Исчерпан общий бюджет 15 секунд")
    process = subprocess.Popen(
        [str(binary), test_filter, "--nocapture", "--test-threads=1", "--color=never"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        stdout, _ = process.communicate(timeout=max(0.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        # Прямой test executable, не shell/Cargo: завершаем только своего ребёнка.
        process.kill()
        stdout, _ = process.communicate()
        output.write_bytes(stdout)
        raise TimeoutError("Превышен общий бюджет 15 секунд; частичный результат отклонён")
    output.write_bytes(stdout)
    text = stdout.decode("utf-8", errors="replace")
    print(text, end="")
    if time.monotonic() > deadline:
        raise TimeoutError("Превышен общий бюджет 15 секунд")
    if process.returncode != 0:
        raise RuntimeError(f"{output.name}: test executable завершился с {process.returncode}")
    summary = re.search(r"test result: ok\. (\d+) passed; 0 failed; 0 ignored;", text)
    if summary is None or int(summary.group(1)) == 0:
        raise RuntimeError(f"{output.name}: нет успешного непустого прогона")
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True, help="Cargo --no-run JSON")
    parser.add_argument("--app", type=Path, required=True, help="Cargo --no-run JSON")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="append", default=[], help="Дополнительный sdk:filter или app:filter")
    args = parser.parse_args()
    binaries = {"sdk": executable(args.sdk), "app": executable(args.app)}
    checks = []
    for item in args.check:
        name, separator, test_filter = item.partition(":")
        if not separator or name not in binaries or not test_filter:
            parser.error("--check требует sdk:filter или app:filter")
        checks.append((name, test_filter))
    # Новый каталог исключает смешивание с успешным результатом старого запуска.
    args.output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    deadline = started + BUDGET_SECONDS
    status = {"accepted": False, "budget_seconds": BUDGET_SECONDS}
    try:
        for name, binary in binaries.items():
            text = run(binary, "perf208_", deadline, args.output / f"{name}.txt")
            rows = re.findall(r"^PERF208 .+$", text, re.MULTILINE)
            if len(rows) != EXPECTED_ROWS[name]:
                raise RuntimeError(f"{name}: строк PERF208 {len(rows)}, ожидалось {EXPECTED_ROWS[name]}")
        for index, (name, test_filter) in enumerate(checks):
            run(binaries[name], test_filter, deadline, args.output / f"check-{index}.txt")
        status["accepted"] = True
    except (TimeoutError, RuntimeError, OSError) as error:
        status["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        status["elapsed_seconds"] = time.monotonic() - started
        (args.output / "status.json").write_text(
            json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    return 0 if status["accepted"] else 1


if __name__ == "__main__":
    sys.exit(main())
