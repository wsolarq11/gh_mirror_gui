[CmdletBinding()]
param(
    [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss'),
    [switch]$SkipGuiSmoke,
    [switch]$SkipNetworkSmoke,
    [switch]$SkipBenchmark,
    [switch]$SkipBenchmarkMatrix
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$EvidenceDir = Join-Path $RepoRoot "target\delivery\$RunId"
$HistoryPath = Join-Path $RepoRoot 'target\bench-history.jsonl'
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

$Receipt = [ordered]@{
    schema_version = 1
    run_id = $RunId
    repo_root = $RepoRoot
    started_at = (Get-Date).ToUniversalTime().ToString('o')
    commands = @()
    checks = [ordered]@{}
    artifacts = [ordered]@{}
}

function Add-CommandResult {
    param(
        [string]$Name,
        [string]$Command,
        [int]$ExitCode,
        [string]$LogPath,
        [double]$DurationSeconds
    )

    $script:Receipt.commands += [ordered]@{
        name = $Name
        command = $Command
        exit_code = $ExitCode
        log = $LogPath
        duration_seconds = [Math]::Round($DurationSeconds, 3)
    }
}

function Invoke-LoggedNative {
    param(
        [string]$Name,
        [string]$Exe,
        [string[]]$Arguments
    )

    Push-Location $RepoRoot
    try {
        $logPath = Join-Path $EvidenceDir "$Name.log"
        $display = (@($Exe) + $Arguments) -join ' '
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $oldErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & $Exe @Arguments 2>&1
            $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        }
        finally {
            $ErrorActionPreference = $oldErrorActionPreference
        }
        $sw.Stop()
        if ($null -eq $output) {
            '' | Set-Content -LiteralPath $logPath -Encoding UTF8
        }
        else {
            $output | Set-Content -LiteralPath $logPath -Encoding UTF8
        }
        Add-CommandResult -Name $Name -Command $display -ExitCode $exitCode -LogPath $logPath -DurationSeconds $sw.Elapsed.TotalSeconds
        if ($exitCode -ne 0) {
            throw "$Name failed with exit code $exitCode"
        }
    }
    finally {
        Pop-Location
    }
}

function Invoke-GitHubLatestRelease {
    param([string]$Repo)

    try {
        $release = Invoke-RestMethod `
            -Headers @{ 'User-Agent' = 'gh_mirror_gui-release-verify' } `
            -Uri "https://api.github.com/repos/$Repo/releases/latest"

        return [ordered]@{
            found = $true
            repo = $Repo
            tag_name = $release.tag_name
            name = $release.name
            published_at = $release.published_at
            html_url = $release.html_url
            body = $release.body
            assets = @($release.assets | ForEach-Object {
                [ordered]@{
                    name = $_.name
                    size = $_.size
                    browser_download_url = $_.browser_download_url
                }
            })
        }
    }
    catch {
        $status = $null
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
        }
        return [ordered]@{
            found = $false
            repo = $Repo
            status_code = $status
            error = $_.Exception.Message
        }
    }
}

function Invoke-NetworkRangeSmoke {
    param(
        [string]$Url,
        [string]$OutFile
    )

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source -L --fail --silent --show-error --range 0-65535 `
            --user-agent 'gh_mirror_gui-release-verify' `
            --output $OutFile `
            $Url
        if ($LASTEXITCODE -ne 0) {
            throw "curl range smoke failed with exit code $LASTEXITCODE"
        }
    }
    else {
        Invoke-WebRequest `
            -Uri $Url `
            -Headers @{ 'User-Agent' = 'gh_mirror_gui-release-verify' } `
            -MaximumRedirection 10 `
            -OutFile $OutFile `
            -UseBasicParsing | Out-Null
    }
    $item = Get-Item -LiteralPath $OutFile
    return [ordered]@{
        ok = ($item.Length -gt 0)
        url = $Url
        output = $OutFile
        bytes = $item.Length
        sha256 = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash
    }
}

function Invoke-CurlBenchmark {
    param(
        [string]$Url,
        [string]$OutFile
    )

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (!$curl) {
        return [ordered]@{ skipped = $true; reason = 'curl.exe not found' }
    }

    $logPath = Join-Path $EvidenceDir 'bench-curl.log'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $output = & $curl.Source -L --fail --silent --show-error `
        --user-agent 'gh_mirror_gui-release-verify' `
        --output $OutFile `
        $Url 2>&1
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    $sw.Stop()
    $output | Set-Content -LiteralPath $logPath -Encoding UTF8
    Add-CommandResult -Name 'bench-curl-latest-asset' -Command "curl.exe -L --fail --output $OutFile $Url" -ExitCode $exitCode -LogPath $logPath -DurationSeconds $sw.Elapsed.TotalSeconds
    if ($exitCode -ne 0) {
        throw "curl benchmark failed with exit code $exitCode"
    }

    $item = Get-Item -LiteralPath $OutFile
    $downloadMs = [Math]::Max(1, [int64]$sw.Elapsed.TotalMilliseconds)
    return [ordered]@{
        status = 'PASS'
        mode = 'curl'
        url = $Url
        output = $OutFile
        total_bytes = $item.Length
        file_bytes = $item.Length
        download_ms = $downloadMs
        total_ms = $downloadMs
        avg_mib_s = ($item.Length / ($downloadMs / 1000.0) / 1MB)
        peak_mib_s = $null
        sha256 = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash
    }
}

function Invoke-BenchVariant {
    param(
        [string]$Name,
        [string]$Url,
        [string]$OutFile,
        [string]$JsonFile,
        [string[]]$ExtraArgs
    )

    Invoke-LoggedNative `
        -Name "bench-$Name" `
        -Exe $exe `
        -Arguments (@(
            '--bench-download',
            '--url', $Url,
            '--out', $OutFile,
            '--json', $JsonFile,
            '--history', $HistoryPath
        ) + $ExtraArgs)

    $bench = Get-Content -LiteralPath $JsonFile -Raw | ConvertFrom-Json
    if ($bench.status -ne 'PASS') {
        throw "benchmark $Name status was $($bench.status)"
    }
    if ((Get-Item -LiteralPath $OutFile).Length -ne $bench.total_bytes) {
        throw "benchmark $Name size mismatch"
    }
    return $bench
}

Invoke-LoggedNative -Name 'git-status' -Exe 'git' -Arguments @('status', '--short', '--branch')
Invoke-LoggedNative -Name 'cargo-fmt-check' -Exe 'cargo' -Arguments @('fmt', '--check')
Invoke-LoggedNative -Name 'cargo-test-all-targets' -Exe 'cargo' -Arguments @('test', '--all-targets')
Invoke-LoggedNative -Name 'cargo-clippy-all-targets' -Exe 'cargo' -Arguments @('clippy', '--all-targets', '--', '-D', 'warnings')
Invoke-LoggedNative -Name 'cargo-build-release' -Exe 'cargo' -Arguments @('build', '--release')

$exe = Join-Path $RepoRoot 'target\release\gh_mirror_gui.exe'
if (!(Test-Path -LiteralPath $exe)) {
    throw "release binary missing: $exe"
}
$exeItem = Get-Item -LiteralPath $exe
$Receipt.artifacts.release_binary = [ordered]@{
    path = $exe
    size = $exeItem.Length
    last_write_time = $exeItem.LastWriteTimeUtc.ToString('o')
    sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
}
$sha256SumsPath = Join-Path $EvidenceDir 'SHA256SUMS.txt'
"$($Receipt.artifacts.release_binary.sha256)  gh_mirror_gui.exe" |
    Set-Content -LiteralPath $sha256SumsPath -Encoding ASCII
$Receipt.artifacts.sha256sums = [ordered]@{
    path = $sha256SumsPath
    size = (Get-Item -LiteralPath $sha256SumsPath).Length
    sha256 = (Get-FileHash -LiteralPath $sha256SumsPath -Algorithm SHA256).Hash
}

$originRelease = Invoke-GitHubLatestRelease -Repo 'wsolarq11/gh_mirror_gui'
$targetRelease = Invoke-GitHubLatestRelease -Repo 'carrot-hu23/dst-admin-go'
$Receipt.checks.origin_latest_release = $originRelease
$Receipt.checks.target_latest_release = $targetRelease

if (!$targetRelease.found) {
    throw 'target latest release lookup failed'
}

$targetAsset = @($targetRelease.assets | Where-Object { $_.name -like '*.tar.gz' } | Select-Object -First 1)[0]
if ($null -eq $targetAsset) {
    throw 'target latest release has no .tar.gz asset'
}

if (!$SkipNetworkSmoke) {
    $Receipt.checks.network_range_smoke = Invoke-NetworkRangeSmoke `
        -Url $targetAsset.browser_download_url `
        -OutFile (Join-Path $EvidenceDir 'network-range-smoke.bin')
}
else {
    $Receipt.checks.network_range_smoke = [ordered]@{ skipped = $true }
}

if (!$SkipBenchmark) {
    $benchOut = Join-Path $EvidenceDir $targetAsset.name
    $benchJson = Join-Path $EvidenceDir 'bench-download.json'
    $bench = Invoke-BenchVariant `
        -Name 'download-latest-asset' `
        -Url $targetAsset.browser_download_url `
        -OutFile $benchOut `
        -JsonFile $benchJson `
        -ExtraArgs @('--mode', 'adaptive')
    $Receipt.checks.download_benchmark = $bench
    $Receipt.artifacts.benchmark_download = [ordered]@{
        path = $benchOut
        json = $benchJson
        size = (Get-Item -LiteralPath $benchOut).Length
        sha256 = (Get-FileHash -LiteralPath $benchOut -Algorithm SHA256).Hash
    }
    if ($bench.status -ne 'PASS') {
        throw "benchmark status was $($bench.status)"
    }
    if ($Receipt.artifacts.benchmark_download.size -ne $bench.total_bytes) {
        throw "benchmark size mismatch"
    }
    if ($Receipt.artifacts.benchmark_download.sha256 -ne $bench.sha256) {
        throw "benchmark sha256 mismatch"
    }

    if (!$SkipBenchmarkMatrix) {
        $variants = @(
            [ordered]@{ name = 'single'; args = @('--mode', 'single') },
            [ordered]@{ name = 'seg-c4-s4m'; args = @('--mode', 'segmented', '--concurrency', '4', '--segment-size', '4194304') },
            [ordered]@{ name = 'seg-c8-s4m'; args = @('--mode', 'segmented', '--concurrency', '8', '--segment-size', '4194304') },
            [ordered]@{ name = 'seg-c16-s4m'; args = @('--mode', 'segmented', '--concurrency', '16', '--segment-size', '4194304') },
            [ordered]@{ name = 'seg-c32-s2m'; args = @('--mode', 'segmented', '--concurrency', '32', '--segment-size', '2097152') }
        )
        $bench | Add-Member -NotePropertyName variant -NotePropertyValue 'auto' -Force
        $matrix = @($bench)
        foreach ($variant in $variants) {
            $out = Join-Path $EvidenceDir ("matrix-$($variant.name)-$($targetAsset.name)")
            $json = Join-Path $EvidenceDir ("matrix-$($variant.name).json")
            $result = Invoke-BenchVariant `
                -Name $variant.name `
                -Url $targetAsset.browser_download_url `
                -OutFile $out `
                -JsonFile $json `
                -ExtraArgs $variant.args
            $result | Add-Member -NotePropertyName variant -NotePropertyValue $variant.name -Force
            $matrix += $result
        }

        $curlOut = Join-Path $EvidenceDir ("matrix-curl-$($targetAsset.name)")
        $curlBench = Invoke-CurlBenchmark -Url $targetAsset.browser_download_url -OutFile $curlOut
        $curlBench | Add-Member -NotePropertyName variant -NotePropertyValue 'curl' -Force
        $matrix += $curlBench
        $winner = @($matrix | Where-Object { $_.status -eq 'PASS' -and $_.avg_mib_s -ne $null } | Sort-Object avg_mib_s -Descending | Select-Object -First 1)[0]
        $Receipt.checks.download_benchmark_matrix = [ordered]@{
            variants = $matrix
            winner = $winner
        }
        $matrixPath = Join-Path $EvidenceDir 'bench-matrix.json'
        $Receipt.checks.download_benchmark_matrix | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $matrixPath -Encoding UTF8
        $Receipt.artifacts.benchmark_matrix = [ordered]@{
            json = $matrixPath
            winner_mode = $winner.mode
            winner_avg_mib_s = $winner.avg_mib_s
            winner_download_ms = $winner.download_ms
        }
    }
    else {
        $Receipt.checks.download_benchmark_matrix = [ordered]@{ skipped = $true }
    }
}
else {
    $Receipt.checks.download_benchmark = [ordered]@{ skipped = $true }
    $Receipt.checks.download_benchmark_matrix = [ordered]@{ skipped = $true }
}

if (!$SkipGuiSmoke) {
    $proc = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3
    $running = !$proc.HasExited
    $exitCode = if ($proc.HasExited) { $proc.ExitCode } else { $null }
    if ($running) {
        Stop-Process -Id $proc.Id -Force
        Wait-Process -Id $proc.Id -ErrorAction SilentlyContinue
    }
    $Receipt.checks.gui_launch_smoke = [ordered]@{
        ok = $running
        process_id = $proc.Id
        observed_running_after_seconds = 3
        exit_code_if_exited = $exitCode
    }
    if (!$running) {
        throw "GUI launch smoke failed; process exited early with code $exitCode"
    }
}
else {
    $Receipt.checks.gui_launch_smoke = [ordered]@{ skipped = $true }
}

$Receipt.completed_at = (Get-Date).ToUniversalTime().ToString('o')
$Receipt.status = 'PASS'
$receiptPath = Join-Path $EvidenceDir 'receipt.json'
$Receipt | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

[ordered]@{
    status = 'PASS'
    receipt = $receiptPath
    release_binary = $Receipt.artifacts.release_binary
    sha256sums = $Receipt.artifacts.sha256sums
} | ConvertTo-Json -Depth 10
