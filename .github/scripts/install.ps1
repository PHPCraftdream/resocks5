#Requires -Version 5.1
# Установить последний стабильный GitHub Release без запуска сервера.
[CmdletBinding()]
param(
    [string] $InstallDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Этот установщик предназначен для Windows. На Linux/macOS используйте install.sh.'
}
$architecture = $env:PROCESSOR_ARCHITEW6432
if ([string]::IsNullOrEmpty($architecture)) {
    $architecture = $env:PROCESSOR_ARCHITECTURE
}
if ($architecture -ne 'AMD64') {
    throw "Готовый Windows-релиз для $architecture не выпускается; требуется x86_64."
}
if (-not $PSBoundParameters.ContainsKey('InstallDir')) {
    if ([string]::IsNullOrEmpty($env:LOCALAPPDATA)) {
        throw 'Не задан LOCALAPPDATA; укажите -InstallDir.'
    }
    $InstallDir = Join-Path $env:LOCALAPPDATA 'resocks5\bin'
}
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    throw 'Каталог установки не может быть пустым.'
}
$InstallDir = [IO.Path]::GetFullPath($InstallDir)

function Save-HttpsFile([uri] $Uri, [string] $Destination) {
    for ($redirect = 0; $redirect -le 5; $redirect++) {
        if ($Uri.Scheme -ne 'https') {
            throw 'Загрузка и все перенаправления должны использовать HTTPS.'
        }
        $request = [Net.HttpWebRequest]::Create($Uri)
        $request.AllowAutoRedirect = $false
        $request.Timeout = 120000
        $request.ReadWriteTimeout = 300000
        $request.UserAgent = 'resocks5-installer'
        $response = $request.GetResponse()
        try {
            $status = [int] $response.StatusCode
            if ($status -in @(301, 302, 303, 307, 308)) {
                $location = $response.Headers['Location']
                if ([string]::IsNullOrEmpty($location)) {
                    throw 'Перенаправление без Location.'
                }
                $Uri = [uri]::new($Uri, $location)
                continue
            }
            if ($status -ne 200) {
                throw "Неожиданный HTTP-статус загрузки: $status"
            }
            $source = $response.GetResponseStream()
            try {
                $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew)
                try { $source.CopyTo($output) }
                finally { $output.Dispose() }
            }
            finally { $source.Dispose() }
            return
        }
        finally { $response.Close() }
    }
    throw 'Слишком много перенаправлений при загрузке.'
}

function Remove-OldBinaries([string] $Directory) {
    try { $files = @(Get-ChildItem -LiteralPath $Directory -File -Force) }
    catch {
        Write-Warning "Не удалось проверить старые бинарники: $($_.Exception.Message)"
        return
    }
    foreach ($file in $files) {
        if ($file.Name -cnotmatch '\A\.resocks5-old-[0-9a-f]{32}\.exe\z' -or
            ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            continue
        }
        $guard = $null
        try {
            # Write-доступ запрещён для активного image; handle закрывает гонку с запуском.
            $guard = [IO.File]::Open($file.FullName, [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite, [IO.FileShare]::Delete)
            [IO.File]::Delete($file.FullName)
            Write-Host "Удалён старый бинарник: $($file.Name)"
        }
        catch [IO.IOException] {
            Write-Warning "Старая копия занята или недоступна, оставлена: $($file.FullName)"
        }
        catch [UnauthorizedAccessException] {
            Write-Warning "Старая копия занята или недоступна, оставлена: $($file.FullName)"
        }
        finally {
            if ($guard) { $guard.Dispose() }
        }
    }
}

$previousTls = [Net.ServicePointManager]::SecurityProtocol
$scratch = $null
$staged = $null
$installLock = $null
try {
    [Net.ServicePointManager]::SecurityProtocol = $previousTls -bor [Net.SecurityProtocolType]::Tls12
    $scratchPath = Join-Path ([IO.Path]::GetTempPath()) ("resocks5-install-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $scratchPath
    $scratch = $scratchPath
    # Загрузки, извлечённые данные и сам скрипт находятся отдельно.
    $metadataDir = Join-Path $scratch 'metadata'
    $archiveDir = Join-Path $scratch 'archive'
    $checksumDir = Join-Path $scratch 'checksums'
    $extractedDir = Join-Path $scratch 'extracted'
    foreach ($directory in @($metadataDir, $archiveDir, $checksumDir, $extractedDir)) {
        $null = New-Item -ItemType Directory -Path $directory
    }
    $metadata = Join-Path $metadataDir 'release.json'
    Save-HttpsFile -Uri 'https://api.github.com/repos/PHPCraftdream/resocks5/releases/latest' -Destination $metadata
    $release = Get-Content -LiteralPath $metadata -Raw | ConvertFrom-Json
    $tag = [string] $release.tag_name
    if ($tag -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._-]*\z') {
        throw 'GitHub вернул недопустимый тег релиза.'
    }
    $asset = 'resocks5-x86_64-pc-windows-msvc.zip'
    $base = "https://github.com/PHPCraftdream/resocks5/releases/download/$tag"
    $archive = Join-Path $archiveDir $asset
    $checksums = Join-Path $checksumDir 'sha256sums.txt'
    Write-Host "Установка resocks5 $tag (Windows x86_64)…"
    Save-HttpsFile -Uri "$base/$asset" -Destination $archive
    Save-HttpsFile -Uri "$base/sha256sums.txt" -Destination $checksums

    $matchingLines = @(Get-Content -LiteralPath $checksums | Where-Object {
        $_ -cmatch ('\A[0-9A-Fa-f]{64}\s+' + [regex]::Escape($asset) + '\z')
    })
    if ($matchingLines.Count -ne 1) {
        throw 'В sha256sums.txt нет единственной корректной записи архива.'
    }
    $expected = ($matchingLines[0] -split '\s+')[0]
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if ($actual -ine $expected) {
        throw 'SHA-256 не совпадает; установка отменена.'
    }

    # Не распаковываем пути из ZIP: читаем только ожидаемый бинарник.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $entries = @($zip.Entries | Where-Object {
            $_.FullName -ceq 'resocks5.exe' -or $_.FullName -ceq './resocks5.exe'
        })
        if ($entries.Count -ne 1 -or $entries[0].Length -le 0) {
            throw 'В архиве нет единственного непустого resocks5.exe.'
        }
        $entry = $entries[0]
        $fileType = ($entry.ExternalAttributes -shr 16) -band 0xF000
        if ($fileType -ne 0 -and $fileType -ne 0x8000) {
            throw 'Бинарник в ZIP не является обычным файлом.'
        }
        $binary = Join-Path $extractedDir 'resocks5.exe'
        $inputStream = $entry.Open()
        try {
            $outputStream = [IO.File]::Open($binary, [IO.FileMode]::CreateNew)
            try {
                $inputStream.CopyTo($outputStream)
            }
            finally {
                $outputStream.Dispose()
            }
        }
        finally {
            $inputStream.Dispose()
        }
        if ((Get-Item -LiteralPath $binary).Length -ne $entry.Length) {
            throw 'Неполный бинарник в ZIP.'
        }
    }
    finally {
        $zip.Dispose()
    }

    $null = New-Item -ItemType Directory -Path $InstallDir -Force
    $lockPath = Join-Path $InstallDir '.resocks5-install.lock'
    $existingLock = Get-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
    if ($existingLock -and ($existingLock.PSIsContainer -or
        ($existingLock.Attributes -band [IO.FileAttributes]::ReparsePoint))) {
        throw "Нельзя использовать каталог или ссылку как блокировку: $lockPath"
    }
    # Файл остаётся на месте, блокировка действует только пока открыт handle.
    $installLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $destination = Join-Path $InstallDir 'resocks5.exe'
    if (Test-Path -LiteralPath $destination) {
        $existing = Get-Item -LiteralPath $destination -Force
        if ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Нельзя заменить каталог или ссылку: $destination"
        }
    }
    # Готовим новый файл до переименования работающего бинарника.
    $stagePath = Join-Path $InstallDir ('.resocks5-' + [guid]::NewGuid().ToString('N') + '.exe')
    $stageStream = [IO.File]::Open($stagePath, [IO.FileMode]::CreateNew)
    $staged = $stagePath
    try {
        $sourceStream = [IO.File]::OpenRead($binary)
        try { $sourceStream.CopyTo($stageStream) }
        finally { $sourceStream.Dispose() }
    }
    finally { $stageStream.Dispose() }
    $backup = $null
    if ([IO.File]::Exists($destination)) {
        $backup = Join-Path $InstallDir ('.resocks5-old-' + [guid]::NewGuid().ToString('N') + '.exe')
        [IO.File]::Move($destination, $backup)
    }
    try {
        [IO.File]::Move($staged, $destination)
        $staged = $null
    }
    catch {
        $installFailure = $_
        if ($backup) {
            try { [IO.File]::Move($backup, $destination) }
            catch {
                throw "Установка не выполнена, восстановление имени тоже не удалось. Старый бинарник сохранён: $backup. Ошибка: $($_.Exception.Message)"
            }
        }
        throw $installFailure
    }
    Remove-OldBinaries -Directory $InstallDir
    Write-Host "Установлено: $destination"
    Write-Host "Добавьте каталог в пользовательский PATH, если его там нет: $InstallDir"
    Write-Host 'Конфиги не изменены; сервер не запущен.'
}
finally {
    [Net.ServicePointManager]::SecurityProtocol = $previousTls
    if ($installLock) { $installLock.Dispose() }
    if ($staged -and (Test-Path -LiteralPath $staged)) {
        Remove-Item -LiteralPath $staged -Force
    }
    if ($scratch -and (Test-Path -LiteralPath $scratch)) {
        Remove-Item -LiteralPath $scratch -Recurse -Force
    }
}
