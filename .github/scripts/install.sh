#!/bin/sh
# Установить последний стабильный GitHub Release без запуска сервера.
set -eu

fail() {
    printf 'resocks5: %s\n' "$*" >&2
    exit 1
}

[ "$#" -le 1 ] || fail 'Использование: sh install.sh [каталог установки]'
for tool in curl tar awk uname mktemp; do
    command -v "$tool" >/dev/null 2>&1 || fail "Необходима команда: $tool"
done

os=$(uname -s)
arch=$(uname -m)
case "$os:$arch" in
    Linux:x86_64|Linux:amd64) target=x86_64-unknown-linux-gnu ;;
    Darwin:arm64|Darwin:aarch64) target=aarch64-apple-darwin ;;
    Darwin:x86_64) target=x86_64-apple-darwin ;;
    *) fail "Готовый релиз для $os/$arch не выпускается. Windows: используйте install.ps1." ;;
esac
if [ "$os" = Linux ] && ls /lib/ld-musl-*.so.1 >/dev/null 2>&1; then
    fail 'Linux-архив требует glibc; musl/Alpine не поддерживается этим установщиком.'
fi

if command -v sha256sum >/dev/null 2>&1; then
    hash_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    hash_tool=shasum
else
    fail 'Необходима команда sha256sum или shasum (SHA-256).'
fi

install_dir=${1:-${HOME:?Не задан HOME}/.local/bin}
case "$install_dir" in
    /*) ;;
    *) install_dir="$PWD/$install_dir" ;;
esac

repo=https://github.com/PHPCraftdream/resocks5
# Фиксируем тег, чтобы архив и checksums не попали из разных релизов.
release_url=$(curl --fail --silent --show-error --location --head \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 20 --max-time 120 --output /dev/null \
    --write-out '%{url_effective}' "$repo/releases/latest") || fail 'Не удалось определить последний релиз.'
case "$release_url" in
    "$repo/releases/tag/"*) tag=${release_url#"$repo/releases/tag/"} ;;
    *) fail "Неожиданный адрес релиза: $release_url" ;;
esac
case "$tag" in
    ''|*[!a-zA-Z0-9._-]*) fail 'Недопустимый тег релиза.' ;;
esac

scratch=$(mktemp -d "${TMPDIR:-/tmp}/resocks5-install.XXXXXXXX")
staged=
cleanup() {
    [ -z "$staged" ] || rm -f -- "$staged"
    rm -rf -- "$scratch"
}
trap cleanup 0
trap 'exit 1' 1 2 15
# Загрузки, извлечённые данные и сам скрипт находятся отдельно.
mkdir "$scratch/archive" "$scratch/checksums" "$scratch/extracted"
asset="resocks5-$target.tar.gz"
base="$repo/releases/download/$tag"
fetch() {
    curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 20 --max-time 300 --output "$2" "$1"
}
printf 'Установка resocks5 %s (%s)…\n' "$tag" "$target"
fetch "$base/$asset" "$scratch/archive/$asset" || fail "Не удалось скачать $asset."
fetch "$base/sha256sums.txt" "$scratch/checksums/sha256sums.txt" || fail 'Не удалось скачать SHA-256.'

expected=$(awk -v name="$asset" '
    $2 == name { count++; hash = $1 }
    END { if (count == 1) print hash; else exit 1 }
' "$scratch/checksums/sha256sums.txt") || fail 'В sha256sums.txt нет единственной записи архива.'
[ "${#expected}" -eq 64 ] || fail 'Некорректная длина SHA-256.'
case "$expected" in *[!a-fA-F0-9]*) fail 'Некорректный SHA-256.' ;; esac
if [ "$hash_tool" = sha256sum ]; then
    actual=$(sha256sum "$scratch/archive/$asset")
else
    actual=$(shasum -a 256 "$scratch/archive/$asset")
fi
actual=${actual%% *}
[ "$actual" = "$expected" ] || fail 'SHA-256 не совпадает; установка отменена.'

# Не распаковываем пути из архива: читаем только один ожидаемый файл.
tar -tzf "$scratch/archive/$asset" > "$scratch/members.txt" || fail 'Повреждён tar.gz.'
member=$(awk '
    $0 == "./resocks5" || $0 == "resocks5" { count++; name = $0 }
    END { if (count == 1) print name; else exit 1 }
' "$scratch/members.txt") || fail 'В архиве нет единственного бинарника resocks5.'
tar -xzOf "$scratch/archive/$asset" "$member" > "$scratch/extracted/resocks5" || fail 'Не удалось извлечь бинарник.'
[ -s "$scratch/extracted/resocks5" ] || fail 'Бинарник пуст.'

mkdir -p -- "$install_dir"
destination="$install_dir/resocks5"
[ ! -L "$destination" ] || fail "Нельзя заменить символическую ссылку: $destination"
[ ! -e "$destination" ] || [ -f "$destination" ] || fail "Это не обычный файл: $destination"
# Временный файл на том же разделе позволяет заменить бинарник атомарно.
staged=$(mktemp "$install_dir/.resocks5.XXXXXXXX")
cat "$scratch/extracted/resocks5" > "$staged"
chmod 755 "$staged"
mv -f -- "$staged" "$destination"
staged=
printf 'Установлено: %s\n' "$destination"
printf 'Добавьте каталог в PATH, если его там нет: %s\n' "$install_dir"
printf 'Конфиги не изменены; сервер не запущен.\n'
