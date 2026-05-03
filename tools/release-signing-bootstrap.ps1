[CmdletBinding()]
param(
    [ValidateSet('Status', 'Bootstrap', 'Preflight')]
    [string]$Action = 'Status',
    [string]$Repo = 'wsolarq11/gh_mirror_gui',
    [string]$TargetTag = 'v0.1.3',
    [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss'),
    [switch]$SetGitHubSecret,
    [switch]$SkipReleaseVerify,
    [switch]$RequireReady
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$SecretName = 'RELEASE_ED25519_PRIVATE_KEY_HEX'
$ProtectedTag = 'v0.1.2'
$ProtectedTagDeref = '7482e7bdfa12c5ccb31e6365e8251e68006366c6'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$OutDir = Join-Path $RepoRoot "target\release-signing-bootstrap\$RunId"
$ReceiptPath = Join-Path $OutDir 'receipt.json'

# Safety contract:
# - release-signing bootstrap writes no private seed to receipt/logs/stdout
# - default path is no-publish and no-mutation
# - the only GitHub mutation path is guarded by -SetGitHubSecret
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Receipt = [ordered]@{
    schema_version = 1
    action = $Action
    repo = $Repo
    run_id = $RunId
    started_at = (Get-Date).ToUniversalTime().ToString('o')
    no_publish = $true
    mutations = @()
    blockers = @()
    warnings = @()
    facts = [ordered]@{}
    artifacts = [ordered]@{}
}

function Add-Blocker {
    param(
        [string]$Code,
        [string]$Detail
    )

    $script:Receipt.blockers += [ordered]@{
        code = $Code
        detail = $Detail
    }
}

function Add-Warning {
    param(
        [string]$Code,
        [string]$Detail
    )

    $script:Receipt.warnings += [ordered]@{
        code = $Code
        detail = $Detail
    }
}

function Write-Receipt {
    param([string]$Status)

    $secretFound = $false
    if ($script:Receipt.facts.Contains('secret')) {
        $secretFound = [bool]$script:Receipt.facts.secret.found
    }

    $targetMatchesPackage = $false
    if ($script:Receipt.facts.Contains('package') -and $script:Receipt.facts.Contains('target')) {
        $targetMatchesPackage = [string]$script:Receipt.facts.package.expected_tag -eq [string]$script:Receipt.facts.target.tag
    }

    $script:Receipt.completed_at = (Get-Date).ToUniversalTime().ToString('o')
    $script:Receipt.status = $Status
    $script:Receipt.next_public_release_ready = (
        $script:Receipt.blockers.Count -eq 0 -and
        $secretFound -and
        $targetMatchesPackage
    )
    $script:Receipt | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
    [ordered]@{
        status = $Status
        next_public_release_ready = $script:Receipt.next_public_release_ready
        receipt = $ReceiptPath
        blockers = $script:Receipt.blockers
        warnings = $script:Receipt.warnings
        no_publish = $true
        mutations = $script:Receipt.mutations
    } | ConvertTo-Json -Depth 8
}

function Invoke-CapturedNative {
    param(
        [string]$Exe,
        [string[]]$Arguments = @()
    )

    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Exe @Arguments 2>&1
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }

    return [ordered]@{
        exit_code = $exitCode
        lines = @($output | ForEach-Object { $_.ToString() })
        text = (@($output | ForEach-Object { $_.ToString() }) -join "`n")
    }
}

function Get-PackageVersion {
    $cargoToml = Join-Path $RepoRoot 'Cargo.toml'
    $versionLine = Select-String -LiteralPath $cargoToml -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($null -eq $versionLine) {
        throw 'Cargo.toml package version not found'
    }
    return [string]$versionLine.Matches[0].Groups[1].Value
}

function Get-SecretStatus {
    $result = Invoke-CapturedNative -Exe 'gh' -Arguments @(
        'secret',
        'list',
        '--repo',
        $Repo,
        '--json',
        'name,updatedAt,visibility'
    )
    if ($result.exit_code -ne 0) {
        Add-Blocker -Code 'gh_secret_list_failed' -Detail "gh secret list failed: $($result.text)"
        return [ordered]@{
            ok = $false
            found = $false
            required_secret = $SecretName
            error = $result.text
        }
    }

    $secrets = @()
    if (![string]::IsNullOrWhiteSpace($result.text)) {
        $parsed = $result.text | ConvertFrom-Json
        $secrets = @($parsed | ForEach-Object { $_ })
    }
    $secretObjects = @($secrets | Where-Object {
            $null -ne $_ -and $null -ne $_.PSObject.Properties['name']
        })
    $match = @($secretObjects | Where-Object {
            [string]$_.PSObject.Properties['name'].Value -eq $SecretName
        })
    if ($match.Count -eq 0) {
        return [ordered]@{
            ok = $true
            found = $false
            required_secret = $SecretName
            total_repo_secrets_visible_to_gh = $secretObjects.Count
        }
    }

    return [ordered]@{
        ok = $true
        found = $true
        required_secret = $SecretName
        updated_at = [string]$match[0].PSObject.Properties['updatedAt'].Value
        visibility = [string]$match[0].PSObject.Properties['visibility'].Value
        total_repo_secrets_visible_to_gh = $secretObjects.Count
    }
}

function Get-ReleaseStatus {
    param([string]$Tag)

    $result = Invoke-CapturedNative -Exe 'gh' -Arguments @(
        'release',
        'view',
        $Tag,
        '--repo',
        $Repo,
        '--json',
        'tagName,name,isDraft,isPrerelease,publishedAt'
    )

    if ($result.exit_code -ne 0) {
        return [ordered]@{
            found = $false
            tag = $Tag
            gh_exit_code = $result.exit_code
            detail = $result.text
        }
    }

    $release = $result.text | ConvertFrom-Json
    return [ordered]@{
        found = $true
        tag = [string]$release.tagName
        name = [string]$release.name
        is_draft = [bool]$release.isDraft
        is_prerelease = [bool]$release.isPrerelease
        published_at = [string]$release.publishedAt
    }
}

function Get-LocalTagDeref {
    param([string]$Tag)

    $result = Invoke-CapturedNative -Exe 'git' -Arguments @('rev-parse', '--verify', "refs/tags/$Tag^{}")
    if ($result.exit_code -ne 0) {
        return [ordered]@{
            found = $false
            tag = $Tag
            detail = $result.text
        }
    }

    return [ordered]@{
        found = $true
        tag = $Tag
        deref = (($result.lines | Select-Object -First 1) -as [string]).Trim()
    }
}

function Get-RemoteTagStatus {
    param([string]$Tag)

    $result = Invoke-CapturedNative -Exe 'git' -Arguments @('ls-remote', 'origin', "refs/tags/$Tag")
    if ($result.exit_code -ne 0) {
        Add-Warning -Code 'remote_tag_probe_failed' -Detail "git ls-remote failed for ${Tag}: $($result.text)"
        return [ordered]@{
            found = $false
            tag = $Tag
            probe_ok = $false
            detail = $result.text
        }
    }

    $line = @($result.lines | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    if ($line.Count -eq 0) {
        return [ordered]@{
            found = $false
            tag = $Tag
            probe_ok = $true
        }
    }

    $parts = ([string]$line[0]) -split '\s+'
    return [ordered]@{
        found = $true
        tag = $Tag
        probe_ok = $true
        ref = if ($parts.Count -gt 1) { $parts[1] } else { '' }
        sha = if ($parts.Count -gt 0) { $parts[0] } else { '' }
    }
}

function Get-GitStatusFacts {
    $status = @(git status --short --branch)
    $head = (git rev-parse HEAD).Trim()
    $branch = @($status | Select-Object -First 1)
    $branchLine = if ($branch.Count -gt 0) { [string]$branch[0] } else { '' }
    $clean = ($status.Count -eq 1 -and $branchLine -match '^\#\# ')
    return [ordered]@{
        head = $head
        branch_line = $branchLine
        status_short = $status
        clean = $clean
        synced_with_upstream = ($clean -and $branchLine -notmatch '\[(ahead|behind|diverged|gone)')
    }
}

function Get-PrivateSeedFromEnv {
    $raw = [Environment]::GetEnvironmentVariable($SecretName, 'Process')
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [ordered]@{
            present = $false
            valid = $false
        }
    }

    $normalized = $raw.Trim().ToUpperInvariant()
    if ($normalized -notmatch '^[0-9A-F]{64}$') {
        Add-Blocker -Code 'local_seed_invalid' -Detail "$SecretName must be a 32-byte Ed25519 seed encoded as 64 hex characters"
        return [ordered]@{
            present = $true
            valid = $false
        }
    }

    return [ordered]@{
        present = $true
        valid = $true
        value = $normalized
    }
}

function Invoke-ReleaseSigningDoctor {
    param([string]$PrivateKeyHex)

    $exe = Join-Path $RepoRoot 'target\release\gh_mirror_gui.exe'
    if (!(Test-Path -LiteralPath $exe)) {
        $build = Invoke-CapturedNative -Exe 'cargo' -Arguments @('build', '--release', '--locked')
        $buildLog = Join-Path $OutDir 'cargo-build-release.log'
        $build.lines | Set-Content -LiteralPath $buildLog -Encoding UTF8
        $script:Receipt.artifacts.cargo_build_release_log = $buildLog
        if ($build.exit_code -ne 0) {
            throw "cargo build --release --locked failed: $($build.text)"
        }
    }

    $doctorDir = Join-Path $OutDir 'release-signing-doctor'
    $doctorJson = Join-Path $doctorDir 'release-signing-readiness.json'
    $publicKeyOut = Join-Path $doctorDir 'publisher-key.ed25519.pub'
    New-Item -ItemType Directory -Force -Path $doctorDir | Out-Null

    $oldReleaseKey = [Environment]::GetEnvironmentVariable($SecretName, 'Process')
    try {
        [Environment]::SetEnvironmentVariable($SecretName, $PrivateKeyHex, 'Process')
        $doctor = Invoke-CapturedNative -Exe $exe -Arguments @(
            '--release-signing-doctor',
            '--fixture-dir',
            $doctorDir,
            '--json',
            $doctorJson,
            '--public-key-out',
            $publicKeyOut
        )
    }
    finally {
        [Environment]::SetEnvironmentVariable($SecretName, $oldReleaseKey, 'Process')
    }

    $doctorLog = Join-Path $OutDir 'release-signing-doctor.log'
    $doctor.lines | Set-Content -LiteralPath $doctorLog -Encoding UTF8
    if ($doctor.exit_code -ne 0) {
        throw "release signing doctor failed: $($doctor.text)"
    }
    if (!(Test-Path -LiteralPath $doctorJson)) {
        throw "release signing doctor JSON missing: $doctorJson"
    }
    if (!(Test-Path -LiteralPath $publicKeyOut)) {
        throw "publisher public key export missing: $publicKeyOut"
    }

    $report = Get-Content -LiteralPath $doctorJson -Raw | ConvertFrom-Json
    return [ordered]@{
        ok = [bool]$report.ok
        json = $doctorJson
        log = $doctorLog
        public_key_export = [ordered]@{
            path = $publicKeyOut
            sha256 = (Get-FileHash -LiteralPath $publicKeyOut -Algorithm SHA256).Hash
            fingerprint_sha256 = [string]$report.public_key.fingerprint_sha256
        }
        required_repository_secret = [string]$report.required_repository_secret
        signature_format = [string]$report.signature_format
        private_key_material = 'not_recorded'
    }
}

function Set-RepositorySecret {
    param([string]$PrivateKeyHex)

    # Use native stdin redirection instead of a PowerShell pipeline. This avoids
    # shell encoding surprises while keeping the seed out of arguments, logs,
    # receipts, files, and stdout.
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'gh'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.Arguments = "secret set $SecretName --repo $Repo"

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (!$process.Start()) {
        throw 'failed to start gh secret set'
    }
    $stdinBytes = [System.Text.Encoding]::ASCII.GetBytes("$PrivateKeyHex`n")
    $process.StandardInput.BaseStream.Write($stdinBytes, 0, $stdinBytes.Length)
    $process.StandardInput.BaseStream.Flush()
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $exitCode = [int]$process.ExitCode

    $setLog = Join-Path $OutDir 'gh-secret-set.log'
    $setLines = @(
        if (![string]::IsNullOrWhiteSpace($stdout)) { $stdout.TrimEnd() }
        if (![string]::IsNullOrWhiteSpace($stderr)) { $stderr.TrimEnd() }
    )
    if ($setLines.Count -eq 0) {
        '' | Set-Content -LiteralPath $setLog -Encoding UTF8
    }
    else {
        $setLines | Set-Content -LiteralPath $setLog -Encoding UTF8
    }
    $script:Receipt.artifacts.github_secret_set_log = $setLog

    if ($exitCode -ne 0) {
        throw "gh secret set failed: $($setLines -join "`n")"
    }

    $script:Receipt.mutations += [ordered]@{
        type = 'github_repository_secret_set'
        repo = $Repo
        secret = $SecretName
        private_key_material = 'not_recorded'
    }
}

function Invoke-ReleaseVerifyPreflight {
    $verifyRunId = "$RunId-signed-preflight"
    $releaseVerify = Join-Path $PSScriptRoot 'release-verify.ps1'
    $result = Invoke-CapturedNative -Exe 'powershell' -Arguments @(
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $releaseVerify,
        '-RunId',
        $verifyRunId,
        '-SkipBenchmarkMatrix'
    )
    $verifyLog = Join-Path $OutDir 'release-verify.log'
    $result.lines | Set-Content -LiteralPath $verifyLog -Encoding UTF8
    $receipt = Join-Path $RepoRoot "target\delivery\$verifyRunId\receipt.json"

    if ($result.exit_code -ne 0) {
        throw "release-verify no-publish preflight failed; see $verifyLog"
    }
    if (!(Test-Path -LiteralPath $receipt)) {
        throw "release-verify no-publish receipt missing: $receipt"
    }

    $verifyReceipt = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
    return [ordered]@{
        ok = ([string]$verifyReceipt.status -eq 'PASS')
        run_id = $verifyRunId
        log = $verifyLog
        receipt = $receipt
        status = [string]$verifyReceipt.status
        signed_release_staging = $verifyReceipt.checks.signed_release_staging
    }
}

Push-Location $RepoRoot
try {
    $git = Get-GitStatusFacts
    $packageVersion = Get-PackageVersion
    $expectedTag = "v$packageVersion"
    $secret = Get-SecretStatus
    $protectedTagStatus = Get-LocalTagDeref -Tag $ProtectedTag
    $targetLocalTag = Get-LocalTagDeref -Tag $TargetTag
    $targetRemoteTag = Get-RemoteTagStatus -Tag $TargetTag
    $targetRelease = Get-ReleaseStatus -Tag $TargetTag
    $protectedRelease = Get-ReleaseStatus -Tag $ProtectedTag

    $Receipt.facts.git = $git
    $Receipt.facts.package = [ordered]@{
        version = $packageVersion
        expected_tag = $expectedTag
    }
    $Receipt.facts.target = [ordered]@{
        tag = $TargetTag
        local_tag = $targetLocalTag
        remote_tag = $targetRemoteTag
        release = $targetRelease
    }
    $Receipt.facts.secret = $secret
    $Receipt.facts.protected_release = [ordered]@{
        tag = $ProtectedTag
        expected_deref = $ProtectedTagDeref
        local_tag = $protectedTagStatus
        release = $protectedRelease
    }

    if (!$protectedTagStatus.found -or [string]$protectedTagStatus.deref -ne $ProtectedTagDeref) {
        Add-Blocker -Code 'protected_v0_1_2_tag_drift' -Detail "$ProtectedTag must deref to $ProtectedTagDeref"
    }
    if (!$protectedRelease.found) {
        Add-Blocker -Code 'protected_v0_1_2_release_missing' -Detail "$ProtectedTag GitHub Release must remain present and unchanged"
    }
    if ($targetLocalTag.found -or $targetRemoteTag.found -or $targetRelease.found) {
        Add-Blocker -Code 'target_tag_or_release_already_exists' -Detail "$TargetTag must not exist for a no-publish preflight"
    }
    if ($TargetTag -ne $expectedTag) {
        Add-Blocker -Code 'target_tag_package_version_mismatch' -Detail "$TargetTag expects Cargo.toml version '$($TargetTag.Substring(1))', current package version is '$packageVersion'"
    }
    if (!$git.clean) {
        Add-Blocker -Code 'git_dirty' -Detail 'release signing preflight must run from a clean git worktree before tagging'
    }
    if (!$git.synced_with_upstream) {
        Add-Blocker -Code 'git_not_synced' -Detail 'release signing preflight must run after main is synced with origin before tagging'
    }

    $seed = Get-PrivateSeedFromEnv
    $Receipt.facts.local_private_seed = [ordered]@{
        env = $SecretName
        present = [bool]$seed.present
        valid = [bool]$seed.valid
        private_key_material = 'not_recorded'
    }

    if ($Action -eq 'Bootstrap' -or $SetGitHubSecret) {
        if (!$seed.present) {
            Add-Blocker -Code 'local_seed_missing' -Detail "Set process environment variable $SecretName before bootstrap; do not pass the seed on the command line"
        }
        elseif ($seed.valid) {
            $Receipt.checks = [ordered]@{
                release_signing_doctor = Invoke-ReleaseSigningDoctor -PrivateKeyHex $seed.value
            }
            if ($SetGitHubSecret) {
                Set-RepositorySecret -PrivateKeyHex $seed.value
                $Receipt.facts.secret = Get-SecretStatus
                $secret = $Receipt.facts.secret
                if (!$secret.found) {
                    Add-Blocker -Code 'secret_set_not_visible' -Detail "$SecretName was set but is not visible in gh secret list"
                }
            }
            else {
                Add-Warning -Code 'secret_not_set_without_explicit_switch' -Detail 'Bootstrap doctor ran, but GitHub secret was not changed because -SetGitHubSecret was not provided'
            }
        }
    }

    if ($Action -eq 'Preflight') {
        if ($SkipReleaseVerify) {
            $Receipt.checks = [ordered]@{
                release_verify = [ordered]@{
                    skipped = $true
                    reason = '-SkipReleaseVerify was provided'
                }
            }
        }
        else {
            $Receipt.checks = [ordered]@{
                release_verify = Invoke-ReleaseVerifyPreflight
            }
        }
    }

    if (!$Receipt.facts.secret.found) {
        Add-Blocker -Code 'secret_missing' -Detail "$SecretName repository secret is missing; release workflow will fail closed before signing"
    }

    $status = if ($Receipt.blockers.Count -eq 0) { 'PASS' } else { 'BLOCKED' }
    Write-Receipt -Status $status
    if (($Action -eq 'Bootstrap' -or $RequireReady) -and $Receipt.blockers.Count -gt 0) {
        exit 2
    }
}
catch {
    Add-Blocker -Code 'script_failed' -Detail $_.Exception.Message
    Write-Receipt -Status 'FAIL'
    exit 1
}
finally {
    Pop-Location
}
