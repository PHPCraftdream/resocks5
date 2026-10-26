"""Проверка установки и обновления работающего сервера только в GitHub CI."""

import collections
import contextlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading


REPO = Path(__file__).resolve().parents[2]
WINDOWS = os.name == "nt"
OLD_NAME = re.compile(r"\.resocks5-old-[0-9a-f]{32}\.exe\Z")


def install(directory):
    if WINDOWS:
        command = [
            "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(REPO / ".github/scripts/install.ps1"),
            "-InstallDir", str(directory),
        ]
    else:
        command = ["sh", str(REPO / ".github/scripts/install.sh"), str(directory)]
    subprocess.run(command, cwd=REPO, check=True, timeout=600)


def backups(directory):
    return [file for file in directory.iterdir() if OLD_NAME.fullmatch(file.name)]


@contextlib.contextmanager
def running_server(binary, directory):
    directory.mkdir()
    (directory / "resocks5.main.ktav").write_text(
        "port: 0\nlisten_host: 127.0.0.1\nauth: { allow_anonymous: false }\n",
        encoding="utf-8",
    )
    (directory / "resocks5.users.ktav").write_text(
        f'users: [ {{ name: "{directory.name}", hash: init, direct: true }} ]\n',
        encoding="utf-8",
    )
    ready = threading.Event()
    state = {"started": False}
    lines = collections.deque(maxlen=32)
    process = subprocess.Popen(
        [binary.name], cwd=directory, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )

    def consume_output():
        try:
            for line in iter(lambda: process.stdout.readline(4096), ""):
                lines.append(line)
                if "Server started on " in line:
                    state["started"] = True
                    ready.set()
        finally:
            ready.set()

    reader = threading.Thread(target=consume_output, daemon=True)
    reader.start()
    try:
        if not ready.wait(30) or not state["started"] or process.poll() is not None:
            raise AssertionError("Сервер не запустился:\n" + "".join(list(lines)))
        yield process
    finally:
        # Завершаем только собственный дочерний процесс, никогда по имени.
        if process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
        reader.join(timeout=5)
        if reader.is_alive():
            raise AssertionError("Поток чтения stdout не завершился.")
        process.stdout.close()


def main():
    with tempfile.TemporaryDirectory(prefix="resocks5-installer-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        root = Path(temporary)
        directory = root / "bin with spaces"
        directory.mkdir()
        marker = directory / "keep.ktav"
        marker.write_bytes(b"keep\n")
        unrelated = directory / ".resocks5-old-user.exe"
        unrelated.write_bytes(b"not an installer backup\n")
        install(directory)
        binary = directory / ("resocks5.exe" if WINDOWS else "resocks5")
        original = binary.stat()
        assert not backups(directory), "Первая установка не должна оставлять старые копии."
        os.environ["PATH"] = str(directory) + os.pathsep + os.environ.get("PATH", "")
        config_names = ("resocks5.main.ktav", "resocks5.proxy_list.ktav", "resocks5.users.ktav")
        for name in config_names:
            (directory / name).write_bytes(b"{\n")

        # Оба процесса ищут бинарник через PATH, но читают разные конфиги из cwd.
        with (
            running_server(binary, root / "server-a") as process_a,
            running_server(binary, root / "server-b") as process_b,
        ):
            install(directory)
            assert process_a.poll() is None and process_b.poll() is None, "Обновление остановило сервер."
            assert binary.stat().st_ino != original.st_ino, "Бинарник не заменён."
            if WINDOWS:
                old = backups(directory)
                assert len(old) == 1, "Работающий старый бинарник должен сохраниться."
                assert old[0].stat().st_ino == original.st_ino, "Старый файл не переименован."
            else:
                assert not backups(directory), "Unix не требует резервных имён для активного inode."
            for state_dir in (root / "server-a", root / "server-b"):
                users = subprocess.run(
                    [binary.name, "users", "list"], cwd=state_dir, check=True,
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
                )
                assert state_dir.name in users.stdout, "Команда users прочитала настройки не из cwd."
                assert all((state_dir / name).is_file() for name in config_names), "Конфиги созданы не в cwd."
            subprocess.run([binary.name, "--version"], cwd=REPO, check=True, timeout=30)
            assert process_a.poll() is None and process_b.poll() is None, "Старые серверы должны работать."

        # После завершения старого процесса следующий запуск убирает его копию.
        install(directory)
        assert not backups(directory), "Неиспользуемые старые бинарники не удалены."
        assert marker.read_bytes() == b"keep\n", "Конфиг изменён установщиком."
        assert unrelated.read_bytes() == b"not an installer backup\n", "Удалён посторонний файл."
        assert all((directory / name).read_bytes() == b"{\n" for name in config_names), "Изменены конфиги рядом с бинарником."
        subprocess.run([binary.name, "--version"], cwd=REPO, check=True, timeout=30)
    print("Установка, конфиги из cwd, обновление работающих процессов и очистка проверены.")


if __name__ == "__main__":
    main()
