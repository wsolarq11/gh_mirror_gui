param(
    # Repo root; defaults to the parent of tools/
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    # Keep only the most recent N delivery runs under target\delivery\<run_id>
    [int]$KeepDeliveryRuns = 8,
    # When set, prune target\{debug,release}\incremental (can reduce size, may slow the next build)
    [switch]$PruneIncremental,
    # Do not delete anything; only print the report JSON
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-DirSizeBytes {
    param([string]$Path)

    if (!(Test-Path -LiteralPath $Path)) {
        return 0
    }

    $files = Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue
    if ($null -eq $files -or $files.Count -eq 0) {
        return 0
    }
    $sum = ($files | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) {
        return 0
    }
    return [int64]$sum
}

function BytesToMiB {
    param([int64]$Bytes)
    return [math]::Round(($Bytes / 1MB), 2)
}

function Remove-Tree {
    param([string]$Path)

    if (!(Test-Path -LiteralPath $Path)) {
        return
    }
    if ($DryRun) {
        return
    }
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
}

$targetRoot = Join-Path $RepoRoot 'target'
$deliveryRoot = Join-Path $targetRoot 'delivery'
$debugIncremental = Join-Path $targetRoot 'debug\\incremental'
$releaseIncremental = Join-Path $targetRoot 'release\\incremental'

$report = [ordered]@{
    schema_version = 1
    started_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    repo_root = $RepoRoot
    dry_run = [bool]$DryRun
    inputs = [ordered]@{
        keep_delivery_runs = $KeepDeliveryRuns
        prune_incremental = [bool]$PruneIncremental
    }
    before = [ordered]@{
        target_mib = (BytesToMiB (Get-DirSizeBytes $targetRoot))
        delivery_mib = (BytesToMiB (Get-DirSizeBytes $deliveryRoot))
        debug_incremental_mib = (BytesToMiB (Get-DirSizeBytes $debugIncremental))
        release_incremental_mib = (BytesToMiB (Get-DirSizeBytes $releaseIncremental))
    }
    actions = @()
}

if (Test-Path -LiteralPath $deliveryRoot) {
    $runDirs = Get-ChildItem -LiteralPath $deliveryRoot -Directory -Force |
        Where-Object { $_.Name -match '^[0-9]{8}-[0-9]{6}$' } |
        Sort-Object Name

    $total = @($runDirs).Count
    if ($total -gt $KeepDeliveryRuns) {
        $deleteCount = $total - $KeepDeliveryRuns
        $toDelete = @($runDirs | Select-Object -First $deleteCount)
        foreach ($dir in $toDelete) {
            $report.actions += [ordered]@{
                action = 'delete_delivery_run'
                path = $dir.FullName
                name = $dir.Name
            }
            Remove-Tree -Path $dir.FullName
        }
    }
}

if ($PruneIncremental) {
    foreach ($path in @($debugIncremental, $releaseIncremental)) {
        if (Test-Path -LiteralPath $path) {
            $report.actions += [ordered]@{
                action = 'delete_incremental_cache'
                path = $path
            }
            Remove-Tree -Path $path
        }
    }
}

$report.after = [ordered]@{
    target_mib = (BytesToMiB (Get-DirSizeBytes $targetRoot))
    delivery_mib = (BytesToMiB (Get-DirSizeBytes $deliveryRoot))
    debug_incremental_mib = (BytesToMiB (Get-DirSizeBytes $debugIncremental))
    release_incremental_mib = (BytesToMiB (Get-DirSizeBytes $releaseIncremental))
}
$report.completed_at_utc = (Get-Date).ToUniversalTime().ToString('o')

$report | ConvertTo-Json -Depth 10

