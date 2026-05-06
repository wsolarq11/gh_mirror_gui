[CmdletBinding()]
param(
    [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss'),
    [switch]$SkipGuiSmoke,
    [switch]$SkipNetworkSmoke,
    [switch]$SkipBenchmark,
    [switch]$SkipBenchmarkMatrix,
    # Artifact hygiene: keep `target\delivery\*` bounded so the repo stays lean without
    # impacting normal development.
    [int]$KeepDeliveryRuns = 8,
    [switch]$PruneTargetIncremental,
    [switch]$SkipTargetGc,
    # Post-publish check: simulate running the previous published release and
    # prove Self-update Stage 2 produces a real-world NO_UPDATE vs STAGED verdict
    # against the currently published latest release (no install / no exe replacement).
    #
    # This is a trust-critical end-to-end gate for "public signed release consumption"
    # and therefore runs by default. Use `-SkipPostPublishSelfUpdateStage2` to skip.
    [switch]$SkipPostPublishSelfUpdateStage2,
    # Back-compat: legacy opt-in flag (kept so older invocations still parse).
    [switch]$PostPublishSelfUpdateStage2
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

function Invoke-CapturedNative {
    param(
        [string]$Name,
        [string]$Exe,
        [string[]]$Arguments = @()
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

        $lines = @($output | ForEach-Object { $_.ToString() })
        if ($lines.Count -eq 0) {
            '' | Set-Content -LiteralPath $logPath -Encoding UTF8
        }
        else {
            $lines | Set-Content -LiteralPath $logPath -Encoding UTF8
        }
        Add-CommandResult -Name $Name -Command $display -ExitCode $exitCode -LogPath $logPath -DurationSeconds $sw.Elapsed.TotalSeconds
        if ($exitCode -ne 0) {
            throw "$Name failed with exit code $exitCode"
        }
        return $lines
    }
    finally {
        Pop-Location
    }
}

function Get-OptionalFileEvidence {
    param([string]$RelativePath)

    $path = Join-Path $RepoRoot $RelativePath
    if (!(Test-Path -LiteralPath $path)) {
        return [ordered]@{
            path = $path
            exists = $false
        }
    }

    $item = Get-Item -LiteralPath $path
    return [ordered]@{
        path = $path
        exists = $true
        size = $item.Length
        last_write_time = $item.LastWriteTimeUtc.ToString('o')
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
}

function Get-FirstLineOrEmpty {
    param([string[]]$Lines)

    if ($null -eq $Lines -or $Lines.Count -eq 0) {
        return ''
    }
    return $Lines[0]
}

function Assert-CommandLogContains {
    param(
        [string]$CommandName,
        [string[]]$RequiredPatterns
    )

    $command = @($Receipt.commands | Where-Object { $_.name -eq $CommandName } | Select-Object -Last 1)
    if ($command.Count -eq 0) {
        throw "required command log not found in receipt: $CommandName"
    }
    $logPath = [string]$command[0].log
    if (!(Test-Path -LiteralPath $logPath)) {
        throw "required command log file missing: $logPath"
    }
    $text = Get-Content -LiteralPath $logPath -Raw
    $missing = @($RequiredPatterns | Where-Object {
        $pattern = [regex]::Escape($_)
        $text -notmatch $pattern
    })
    if ($missing.Count -gt 0) {
        throw "$CommandName log missing required trust-policy evidence: $($missing -join ', ')"
    }

    return [ordered]@{
        ok = $true
        command = $CommandName
        log = $logPath
        required_patterns = $RequiredPatterns
    }
}

function Assert-FileContains {
    param(
        [string]$RelativePath,
        [string[]]$RequiredPatterns
    )

    $path = Join-Path $RepoRoot $RelativePath
    if (!(Test-Path -LiteralPath $path)) {
        throw "required guardrail file missing: $RelativePath"
    }
    $text = Get-Content -LiteralPath $path -Raw
    $missing = @($RequiredPatterns | Where-Object {
        $pattern = [regex]::Escape($_)
        $text -notmatch $pattern
    })
    if ($missing.Count -gt 0) {
        throw "$RelativePath missing required route guardrails: $($missing -join ', ')"
    }

    return [ordered]@{
        ok = $true
        path = $path
        required_patterns = $RequiredPatterns
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
}

function Get-WorkflowStepBlock {
    param(
        [string[]]$Lines,
        [string]$StepName,
        [string]$RelativePath
    )

    $start = -1
    $stepPattern = "^\s*-\s+name:\s+$([regex]::Escape($StepName))\s*$"
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match $stepPattern) {
            $start = $i
            break
        }
    }
    if ($start -lt 0) {
        throw "$RelativePath missing required workflow step: $StepName"
    }

    $end = $Lines.Count - 1
    for ($i = $start + 1; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '^\s*-\s+name:\s+') {
            $end = $i - 1
            break
        }
    }

    $blockLines = @()
    if ($end -ge $start) {
        $blockLines = @($Lines[$start..$end])
    }

    return [ordered]@{
        name = $StepName
        start_line = $start + 1
        end_line = $end + 1
        text = ($blockLines -join "`n")
    }
}

function Assert-TextContainsAll {
    param(
        [string]$Text,
        [string]$Label,
        [string[]]$RequiredPatterns
    )

    $missing = @($RequiredPatterns | Where-Object {
        $pattern = [regex]::Escape($_)
        $Text -notmatch $pattern
    })
    if ($missing.Count -gt 0) {
        throw "$Label missing required artifact contract patterns: $($missing -join ', ')"
    }

    return $RequiredPatterns
}

function Assert-TextDoesNotContain {
    param(
        [string]$Text,
        [string]$Label,
        [string[]]$ForbiddenPatterns
    )

    $present = @($ForbiddenPatterns | Where-Object {
        $pattern = [regex]::Escape($_)
        $Text -match $pattern
    })
    if ($present.Count -gt 0) {
        throw "$Label contains forbidden mutation or secret-leak pattern: $($present -join ', ')"
    }

    return $ForbiddenPatterns
}

function Assert-TextPatternOrder {
    param(
        [string]$Text,
        [string]$Label,
        [string[]]$RequiredPatterns
    )

    $lastIndex = -1
    foreach ($pattern in $RequiredPatterns) {
        $index = $Text.IndexOf($pattern, [System.StringComparison]::Ordinal)
        if ($index -lt 0) {
            throw "$Label missing required ordered artifact contract pattern: $pattern"
        }
        if ($index -le $lastIndex) {
            throw "$Label artifact contract order mismatch at pattern: $pattern"
        }
        $lastIndex = $index
    }

    return $RequiredPatterns
}

function Assert-ReleaseWorkflowArtifactContract {
    $relativePath = '.github\workflows\release.yml'
    $path = Join-Path $RepoRoot $relativePath
    if (!(Test-Path -LiteralPath $path)) {
        throw "required release workflow missing: $relativePath"
    }

    $lines = @(Get-Content -LiteralPath $path)
    $stageBlock = Get-WorkflowStepBlock -Lines $lines -StepName 'Stage release assets' -RelativePath $relativePath
    $uploadArtifactBlock = Get-WorkflowStepBlock -Lines $lines -StepName 'Upload release build artifact' -RelativePath $relativePath
    $createReleaseBlock = Get-WorkflowStepBlock -Lines $lines -StepName 'Create GitHub Release' -RelativePath $relativePath

    $requiredStagedAssets = @(
        'gh_mirror_gui.exe',
        'SHA256SUMS.txt',
        'SHA256SUMS.txt.sig',
        'release-provenance.json',
        'release-provenance.json.sig',
        'publisher-key.ed25519.pub'
    )
    $explicitReleaseUploadAssets = @(
        'dist\gh_mirror_gui.exe',
        'dist\SHA256SUMS.txt',
        'dist\release-provenance.json',
        'dist\publisher-key.ed25519.pub'
    )
    $signatureAssets = @(
        'SHA256SUMS.txt.sig',
        'release-provenance.json.sig'
    )

    $stageRequiredPatterns = @(
        'RELEASE_ED25519_PRIVATE_KEY_HEX repository secret is required; refusing unsigned release.',
        '--release-signing-doctor',
        '--public-key-out $publicKeyAsset',
        'publisher-key.ed25519.pub',
        'SHA256SUMS.txt.sig',
        'release-provenance.json.sig',
        '--sign-verification-source',
        '--source (Join-Path $dist "SHA256SUMS.txt")',
        '--out (Join-Path $dist "SHA256SUMS.txt.sig")',
        '--source (Join-Path $dist "release-provenance.json")',
        '--out (Join-Path $dist "release-provenance.json.sig")'
    )
    $stageCovered = Assert-TextContainsAll `
        -Text ([string]$stageBlock.text) `
        -Label "$relativePath step '$($stageBlock.name)'" `
        -RequiredPatterns $stageRequiredPatterns
    $stageOrder = Assert-TextPatternOrder `
        -Text ([string]$stageBlock.text) `
        -Label "$relativePath step '$($stageBlock.name)'" `
        -RequiredPatterns @(
            'RELEASE_ED25519_PRIVATE_KEY_HEX repository secret is required; refusing unsigned release.',
            '--release-signing-doctor',
            '$provenance | ConvertTo-Json -Depth 10',
            '--source (Join-Path $dist "SHA256SUMS.txt")',
            '--source (Join-Path $dist "release-provenance.json")'
        )

    $uploadArtifactCovered = Assert-TextContainsAll `
        -Text ([string]$uploadArtifactBlock.text) `
        -Label "$relativePath step '$($uploadArtifactBlock.name)'" `
        -RequiredPatterns @(
            'path: dist/*',
            'if-no-files-found: error'
        )

    $createReleaseCovered = Assert-TextContainsAll `
        -Text ([string]$createReleaseBlock.text) `
        -Label "$relativePath step '$($createReleaseBlock.name)'" `
        -RequiredPatterns (@(
            'gh release create $env:RELEASE_TAG @assets',
            '--verify-tag',
            '$assets += @(Get-ChildItem -LiteralPath dist -Filter "*.sig"'
        ) + $explicitReleaseUploadAssets)
    $createReleaseOrder = Assert-TextPatternOrder `
        -Text ([string]$createReleaseBlock.text) `
        -Label "$relativePath step '$($createReleaseBlock.name)'" `
        -RequiredPatterns @(
            '$assets = @(',
            '$assets += @(Get-ChildItem -LiteralPath dist -Filter "*.sig"',
            'gh release create $env:RELEASE_TAG @assets',
            '--verify-tag'
        )

    return [ordered]@{
        ok = $true
        path = $path
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        fail_fast_checks = [ordered]@{
            unsigned_release_refused_before_staging = $true
            signing_doctor_required = $true
            staged_signatures_generated_before_release_create = $true
            upload_artifact_fails_on_missing_dist_assets = $true
            create_release_uses_verify_tag = $true
            create_release_uploads_explicit_non_signature_assets = $true
            create_release_uploads_signature_assets_by_dist_sig_glob = $true
        }
        required_staged_assets = $requiredStagedAssets
        explicit_release_upload_assets = $explicitReleaseUploadAssets
        signature_assets = $signatureAssets
        steps = [ordered]@{
            stage_release_assets = [ordered]@{
                start_line = [int]$stageBlock.start_line
                end_line = [int]$stageBlock.end_line
                required_patterns = $stageCovered
                ordered_patterns = $stageOrder
            }
            upload_release_build_artifact = [ordered]@{
                start_line = [int]$uploadArtifactBlock.start_line
                end_line = [int]$uploadArtifactBlock.end_line
                required_patterns = $uploadArtifactCovered
            }
            create_github_release = [ordered]@{
                start_line = [int]$createReleaseBlock.start_line
                end_line = [int]$createReleaseBlock.end_line
                required_patterns = $createReleaseCovered
                ordered_patterns = $createReleaseOrder
            }
        }
    }
}

function Assert-ReleaseSigningBootstrapContract {
    $relativePath = 'tools\release-signing-bootstrap.ps1'
    $path = Join-Path $RepoRoot $relativePath
    if (!(Test-Path -LiteralPath $path)) {
        throw "required release signing bootstrap helper missing: $relativePath"
    }

    $text = Get-Content -LiteralPath $path -Raw
    $requiredPatterns = @(
        "ValidateSet('Status', 'Bootstrap', 'Preflight')",
        '[switch]$SetGitHubSecret',
        '$SecretName = ''RELEASE_ED25519_PRIVATE_KEY_HEX''',
        '$ProtectedTag = ''v0.1.2''',
        '$ProtectedTagDeref = ''7482e7bdfa12c5ccb31e6365e8251e68006366c6''',
        'release-signing bootstrap writes no private seed to receipt/logs/stdout',
        'no_publish = $true',
        'private_key_material = ''not_recorded''',
        '$secretStdinEnv = ''GH_MIRROR_GUI_SECRET_STDIN''',
        '"$SecretName=$PrivateKeyHex"',
        'cmd.exe /D /C "echo(%$secretStdinEnv%| gh secret set -f - --repo $Repo"',
        'Protect-SecretOutput',
        '--release-signing-doctor',
        'release-verify.ps1',
        '-SkipBenchmarkMatrix',
        'secret_missing',
        'target_tag_package_version_mismatch',
        '$Action -eq ''Bootstrap'' -or $SetGitHubSecret'
    )
    $forbiddenPatterns = @(
        'gh release create',
        'gh release upload',
        'gh release delete',
        'git tag -a',
        'git push origin',
        '$PrivateKeyHex | gh secret set',
        '$PrivateKeyHex | Set-Content',
        '$PrivateKeyHex | Add-Content',
        'Write-Host $PrivateKeyHex'
    )

    return [ordered]@{
        ok = $true
        path = $path
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        default_no_publish = $true
        mutating_path_requires_set_github_secret = $true
        release_verify_remains_delivery_judge = $true
        required_patterns = Assert-TextContainsAll `
            -Text $text `
            -Label $relativePath `
            -RequiredPatterns $requiredPatterns
        forbidden_patterns_absent = Assert-TextDoesNotContain `
            -Text $text `
            -Label $relativePath `
            -ForbiddenPatterns $forbiddenPatterns
    }
}

function Assert-TrustCenterBackendContract {
    $contractRelativePath = 'src\trust_center.rs'
    $mainRelativePath = 'src\main.rs'
    $uiRelativePath = 'src\gui_app.rs'
    $contractPath = Join-Path $RepoRoot $contractRelativePath
    $mainPath = Join-Path $RepoRoot $mainRelativePath
    $uiPath = Join-Path $RepoRoot $uiRelativePath
    if (!(Test-Path -LiteralPath $contractPath)) {
        throw "Trust Center backend contract module missing: $contractRelativePath"
    }
    if (!(Test-Path -LiteralPath $mainPath)) {
        throw "UI shell missing: $mainRelativePath"
    }
    if (!(Test-Path -LiteralPath $uiPath)) {
        throw "UI app module missing: $uiRelativePath"
    }

    $contractText = Get-Content -LiteralPath $contractPath -Raw
    $mainText = Get-Content -LiteralPath $mainPath -Raw
    $uiText = Get-Content -LiteralPath $uiPath -Raw
    $contractCovered = Assert-TextContainsAll `
        -Text $contractText `
        -Label $contractRelativePath `
        -RequiredPatterns @(
            'pub(crate) struct TrustCenterSnapshot',
            'pub(crate) fn trust_center_snapshot',
            'VerificationReport',
            'TrustPolicySnapshot',
            'AppliedFileDisposition',
            'publisher_key_source_label_for_policy',
            'evidence_access_status'
        )
    if ($contractText -match '\begui\b|\beframe\b') {
        throw "$contractRelativePath must remain UI-framework-free; found egui/eframe reference"
    }
    if ($mainText -match '(?m)^\s*fn\s+trust_center_snapshot\s*\(') {
        throw "$mainRelativePath must render Trust Center snapshots, not construct backend trust snapshots"
    }
    if ($uiText -match '(?m)^\s*fn\s+trust_center_snapshot\s*\(') {
        throw "$uiRelativePath must render Trust Center snapshots, not construct backend trust snapshots"
    }
    $uiCovered = Assert-TextContainsAll `
        -Text $uiText `
        -Label $uiRelativePath `
        -RequiredPatterns @(
            'gh_mirror_gui::backend_contract',
            'trust_center_snapshot',
            'render_trust_center_snapshot'
        )

    return [ordered]@{
        ok = $true
        contract = 'Trust Center snapshot is a UI-framework-free backend/core DTO; gui_app renders it without owning final trust verdict construction'
        module = [ordered]@{
            path = $contractPath
            sha256 = (Get-FileHash -LiteralPath $contractPath -Algorithm SHA256).Hash
            required_patterns = $contractCovered
            ui_framework_free = $true
        }
        ui_shell = [ordered]@{
            path = $mainPath
            sha256 = (Get-FileHash -LiteralPath $mainPath -Algorithm SHA256).Hash
            required_patterns = @()
            owns_rendering_only = $true
        }
        ui_app = [ordered]@{
            path = $uiPath
            sha256 = (Get-FileHash -LiteralPath $uiPath -Algorithm SHA256).Hash
            required_patterns = $uiCovered
            owns_rendering_only = $true
        }
    }
}

function Assert-UiShellThinness {
    $moduleContracts = @(
        [ordered]@{
            path = 'src\gui_app.rs'
            required = @(
                'gh_mirror_gui::backend_contract',
                'crate::gui_trust_center',
                'crate::gui_update_candidate',
                'build_update_apply_plan_for_stage2'
            )
            forbidden = @(
                'crate::download',
                'crate::verification',
                'crate::source_trust',
                'crate::trust_policy',
                'crate::releases',
                'crate::core_runtime',
                'crate::update_candidate',
                'crate::history',
                'crate::evidence_ledger',
                'crate::source_adapter',
                'crate::verifier_adapter',
                'crate::staged_release',
                'crate::url_policy'
            )
        }
        [ordered]@{
            path = 'src\gui_trust_center.rs'
            required = @('gh_mirror_gui::backend_contract')
            forbidden = @(
                'crate::download',
                'crate::verification',
                'crate::source_trust',
                'crate::trust_policy',
                'crate::releases',
                'crate::core_runtime',
                'crate::update_candidate',
                'crate::history',
                'crate::evidence_ledger',
                'crate::source_adapter',
                'crate::verifier_adapter',
                'crate::staged_release',
                'crate::url_policy'
            )
        }
        [ordered]@{
            path = 'src\gui_update_candidate.rs'
            required = @(
                'gh_mirror_gui::backend_contract',
                'render_update_apply_plan_preview',
                'UpdateApplyPlan'
            )
            forbidden = @(
                'crate::download',
                'crate::verification',
                'crate::source_trust',
                'crate::trust_policy',
                'crate::releases',
                'crate::core_runtime',
                'crate::update_candidate',
                'crate::history',
                'crate::evidence_ledger',
                'crate::source_adapter',
                'crate::verifier_adapter',
                'crate::staged_release',
                'crate::url_policy'
            )
        }
    )

    $results = [ordered]@{}
    foreach ($moduleContract in $moduleContracts) {
        $relativePath = $moduleContract.path
        $path = Join-Path $RepoRoot $relativePath
        if (!(Test-Path -LiteralPath $path)) {
            throw "UI shell module missing: $relativePath"
        }

        $text = Get-Content -LiteralPath $path -Raw
        $required = Assert-TextContainsAll `
            -Text $text `
            -Label $relativePath `
            -RequiredPatterns $moduleContract.required
        $forbidden = Assert-TextDoesNotContain `
            -Text $text `
            -Label $relativePath `
            -ForbiddenPatterns $moduleContract.forbidden
        $results[$relativePath] = [ordered]@{
            path = $path
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            required_patterns = $required
            forbidden_patterns_absent = $forbidden
        }
    }

    return [ordered]@{
        ok = $true
        contract = 'UI shell modules stay thin: gui_app coordinates through backend_contract, and gui_trust_center/gui_update_candidate only render backend DTOs'
        modules = $results
    }
}

function Invoke-ReleaseSigningReadiness {
    param(
        [string]$Exe,
        [string]$FixtureDir,
        [string]$JsonFile,
        [string]$PublicKeyOut
    )

    $testPrivateKey = '1111111111111111111111111111111111111111111111111111111111111111'
    $oldReleaseKey = $env:RELEASE_ED25519_PRIVATE_KEY_HEX
    $oldLegacyKey = $env:GH_MIRROR_GUI_ED25519_PRIVATE_KEY_HEX
    try {
        $env:RELEASE_ED25519_PRIVATE_KEY_HEX = $testPrivateKey
        Remove-Item Env:GH_MIRROR_GUI_ED25519_PRIVATE_KEY_HEX -ErrorAction SilentlyContinue
        Invoke-LoggedNative `
            -Name 'release-signing-doctor' `
            -Exe $Exe `
            -Arguments @(
                '--release-signing-doctor',
                '--fixture-dir', $FixtureDir,
                '--json', $JsonFile,
                '--public-key-out', $PublicKeyOut
            )
    }
    finally {
        if ($null -eq $oldReleaseKey) {
            Remove-Item Env:RELEASE_ED25519_PRIVATE_KEY_HEX -ErrorAction SilentlyContinue
        }
        else {
            $env:RELEASE_ED25519_PRIVATE_KEY_HEX = $oldReleaseKey
        }
        if ($null -eq $oldLegacyKey) {
            Remove-Item Env:GH_MIRROR_GUI_ED25519_PRIVATE_KEY_HEX -ErrorAction SilentlyContinue
        }
        else {
            $env:GH_MIRROR_GUI_ED25519_PRIVATE_KEY_HEX = $oldLegacyKey
        }
    }

    if (!(Test-Path -LiteralPath $JsonFile)) {
        throw "release signing doctor JSON missing: $JsonFile"
    }
    if (!(Test-Path -LiteralPath $PublicKeyOut)) {
        throw "release signing public key export missing: $PublicKeyOut"
    }
    $doctor = Get-Content -LiteralPath $JsonFile -Raw | ConvertFrom-Json
    if (!$doctor.ok) {
        throw "release signing doctor did not report ok=true"
    }
    if ([string]$doctor.required_repository_secret -ne 'RELEASE_ED25519_PRIVATE_KEY_HEX') {
        throw "release signing doctor required_repository_secret mismatch"
    }
    if ([string]$doctor.signature_format -ne 'ed25519-detached-hex') {
        throw "release signing doctor signature format mismatch"
    }
    $requiredAssets = @($doctor.next_release_required_assets | ForEach-Object { [string]$_ })
    $missingAssets = @(@(
            'SHA256SUMS.txt.sig',
            'release-provenance.json.sig',
            'publisher-key.ed25519.pub'
        ) | Where-Object { $requiredAssets -notcontains $_ })
    if ($missingAssets.Count -gt 0) {
        throw "release signing doctor missing next-release asset contract: $($missingAssets -join ', ')"
    }
    $signaturePath = Join-Path $FixtureDir 'SHA256SUMS.txt.sig'
    if (!(Test-Path -LiteralPath $signaturePath)) {
        throw "release signing fixture signature missing: $signaturePath"
    }
    $signature = (Get-Content -LiteralPath $signaturePath -Raw).Trim()
    if ($signature -notmatch '^[0-9A-F]{128}$') {
        throw "release signing fixture signature was not 128 uppercase hex characters"
    }
    $publicKey = (Get-Content -LiteralPath $PublicKeyOut -Raw).Trim()
    if ($publicKey -notmatch '^[0-9A-F]{64}$') {
        throw "release signing public key export was not 64 uppercase hex characters"
    }
    if ([string]$doctor.public_key.fingerprint_sha256 -notmatch '^[0-9A-F]{64}$') {
        throw "release signing public key fingerprint was not 64 uppercase hex characters"
    }

    return [ordered]@{
        ok = $true
        command = 'release-signing-doctor'
        json = $JsonFile
        fixture_dir = $FixtureDir
        public_key_export = [ordered]@{
            path = $PublicKeyOut
            sha256 = (Get-FileHash -LiteralPath $PublicKeyOut -Algorithm SHA256).Hash
            fingerprint_sha256 = [string]$doctor.public_key.fingerprint_sha256
        }
        required_repository_secret = [string]$doctor.required_repository_secret
        signature_format = [string]$doctor.signature_format
        fixture = $doctor.fixture
        next_release_required_assets = $requiredAssets
    }
}

function Get-CargoPackageVersion {
    $cargoToml = Join-Path $RepoRoot 'Cargo.toml'
    $versionLine = Select-String -LiteralPath $cargoToml -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($null -eq $versionLine) {
        throw 'Cargo.toml package version not found'
    }
    return $versionLine.Matches[0].Groups[1].Value
}

function Assert-UpperHexTextFile {
    param(
        [string]$Path,
        [int]$ExpectedChars,
        [string]$Label
    )

    if (!(Test-Path -LiteralPath $Path)) {
        throw "$Label missing: $Path"
    }
    $text = (Get-Content -LiteralPath $Path -Raw).Trim()
    if ($text -notmatch "^[0-9A-F]{$ExpectedChars}$") {
        throw "$Label must be $ExpectedChars uppercase hex characters"
    }
    return $text
}

function Assert-StagedReleaseProvenance {
    param(
        [string]$Path,
        [string]$ExpectedPackageVersion,
        [string]$ExpectedBinarySha256,
        [string]$ExpectedSha256SumsSha256,
        [string]$ExpectedPublisherKeySha256,
        [string]$ExpectedPublisherKeyFingerprint
    )

    if (!(Test-Path -LiteralPath $Path)) {
        throw "staged release provenance missing: $Path"
    }
    $provenance = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ([int]$provenance.schema_version -ne 1) {
        throw 'staged release-provenance.json schema_version mismatch'
    }
    if ($provenance.dry_run -ne $true) {
        throw 'staged release-provenance.json must declare dry_run=true'
    }
    if ([string]$provenance.package_version -ne $ExpectedPackageVersion) {
        throw "staged release-provenance.json package_version mismatch: $($provenance.package_version)"
    }
    if ([string]$provenance.artifacts.release_binary.path -ne 'gh_mirror_gui.exe') {
        throw "staged release-provenance.json release_binary.path mismatch: $($provenance.artifacts.release_binary.path)"
    }
    if (([string]$provenance.artifacts.release_binary.sha256).ToUpperInvariant() -ne $ExpectedBinarySha256) {
        throw 'staged release-provenance.json release binary hash mismatch'
    }
    if ([string]$provenance.artifacts.sha256sums.path -ne 'SHA256SUMS.txt') {
        throw "staged release-provenance.json sha256sums.path mismatch: $($provenance.artifacts.sha256sums.path)"
    }
    if (([string]$provenance.artifacts.sha256sums.sha256).ToUpperInvariant() -ne $ExpectedSha256SumsSha256) {
        throw 'staged release-provenance.json SHA256SUMS hash mismatch'
    }
    if ([string]$provenance.artifacts.publisher_public_key.path -ne 'publisher-key.ed25519.pub') {
        throw "staged release-provenance.json publisher key path mismatch: $($provenance.artifacts.publisher_public_key.path)"
    }
    if (([string]$provenance.artifacts.publisher_public_key.sha256).ToUpperInvariant() -ne $ExpectedPublisherKeySha256) {
        throw 'staged release-provenance.json publisher key asset hash mismatch'
    }
    if (([string]$provenance.artifacts.publisher_public_key.fingerprint_sha256).ToUpperInvariant() -ne $ExpectedPublisherKeyFingerprint) {
        throw 'staged release-provenance.json publisher key fingerprint mismatch'
    }
    if ([int]$provenance.source_trust.schema_version -ne 1) {
        throw 'staged release-provenance.json source_trust schema mismatch'
    }
    if ([string]$provenance.source_trust.signature_format -ne 'ed25519-detached-hex') {
        throw 'staged release-provenance.json source_trust signature_format mismatch'
    }
    if ([string]$provenance.source_trust.publisher_public_key_asset -ne 'publisher-key.ed25519.pub') {
        throw 'staged release-provenance.json source_trust publisher key asset mismatch'
    }
    if (([string]$provenance.source_trust.publisher_public_key_sha256_fingerprint).ToUpperInvariant() -ne $ExpectedPublisherKeyFingerprint) {
        throw 'staged release-provenance.json source_trust publisher key fingerprint mismatch'
    }
    $signedAssets = @($provenance.source_trust.signed_assets | ForEach-Object { [string]$_ })
    $missingSignedAssets = @(@('SHA256SUMS.txt.sig', 'release-provenance.json.sig') | Where-Object { $signedAssets -notcontains $_ })
    if ($missingSignedAssets.Count -gt 0) {
        throw "staged release-provenance.json missing signed asset contract: $($missingSignedAssets -join ', ')"
    }

    return [ordered]@{
        ok = $true
        path = $Path
        schema_version = [int]$provenance.schema_version
        dry_run = [bool]$provenance.dry_run
        release_tag = [string]$provenance.release_tag
        package_version = [string]$provenance.package_version
        source_trust = [ordered]@{
            schema_version = [int]$provenance.source_trust.schema_version
            signature_format = [string]$provenance.source_trust.signature_format
            publisher_public_key_asset = [string]$provenance.source_trust.publisher_public_key_asset
            publisher_public_key_sha256_fingerprint = [string]$provenance.source_trust.publisher_public_key_sha256_fingerprint
            signed_assets = $signedAssets
        }
    }
}

function Invoke-SignedReleaseStagingSelfTest {
    param(
        [string]$Exe,
        [string]$StageDir
    )

    $testPrivateKey = '1111111111111111111111111111111111111111111111111111111111111111'
    $oldReleaseKey = $env:RELEASE_ED25519_PRIVATE_KEY_HEX
    $oldLegacyKey = $env:GH_MIRROR_GUI_ED25519_PRIVATE_KEY_HEX
    $assetExe = Join-Path $StageDir 'gh_mirror_gui.exe'
    $sha256SumsPath = Join-Path $StageDir 'SHA256SUMS.txt'
    $sha256SumsSignaturePath = Join-Path $StageDir 'SHA256SUMS.txt.sig'
    $provenancePath = Join-Path $StageDir 'release-provenance.json'
    $provenanceSignaturePath = Join-Path $StageDir 'release-provenance.json.sig'
    $publicKeyAsset = Join-Path $StageDir 'publisher-key.ed25519.pub'
    $doctorJson = Join-Path $StageDir 'release-signing-readiness.json'
    $doctorFixtureDir = Join-Path $StageDir 'doctor-fixture'
    $sha256SumsVerifyJson = Join-Path $StageDir 'SHA256SUMS.txt.sig.verify.json'
    $provenanceVerifyJson = Join-Path $StageDir 'release-provenance.json.sig.verify.json'
    $downloadSelfTestJson = Join-Path $StageDir 'staged-release-download-selftest.json'

    try {
        $env:RELEASE_ED25519_PRIVATE_KEY_HEX = $testPrivateKey
        Remove-Item Env:GH_MIRROR_GUI_ED25519_PRIVATE_KEY_HEX -ErrorAction SilentlyContinue

        New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
        Copy-Item -LiteralPath $Exe -Destination $assetExe -Force
        $exeHash = (Get-FileHash -LiteralPath $assetExe -Algorithm SHA256).Hash
        "$exeHash  gh_mirror_gui.exe" | Set-Content -LiteralPath $sha256SumsPath -Encoding ASCII
        $sha256SumsHash = (Get-FileHash -LiteralPath $sha256SumsPath -Algorithm SHA256).Hash

        Invoke-LoggedNative `
            -Name 'signed-release-staging-doctor' `
            -Exe $Exe `
            -Arguments @(
                '--release-signing-doctor',
                '--fixture-dir', $doctorFixtureDir,
                '--json', $doctorJson,
                '--public-key-out', $publicKeyAsset
            )

        $doctor = Get-Content -LiteralPath $doctorJson -Raw | ConvertFrom-Json
        if (!$doctor.ok) {
            throw 'signed release staging doctor did not report ok=true'
        }
        $publisherKeyFingerprint = ([string]$doctor.public_key.fingerprint_sha256).ToUpperInvariant()
        if ($publisherKeyFingerprint -notmatch '^[0-9A-F]{64}$') {
            throw 'signed release staging publisher key fingerprint was not 64 uppercase hex characters'
        }
        $publisherKeyText = Assert-UpperHexTextFile -Path $publicKeyAsset -ExpectedChars 64 -Label 'signed release staging publisher key'
        $publisherKeyHash = (Get-FileHash -LiteralPath $publicKeyAsset -Algorithm SHA256).Hash

        $packageVersion = Get-CargoPackageVersion
        $stagingTag = "v$packageVersion-signed-staging"
        $provenance = [ordered]@{
            schema_version = 1
            dry_run = $true
            release_tag = $stagingTag
            package_version = $packageVersion
            generated_by = 'tools\release-verify.ps1 signed_release_staging'
            git = [ordered]@{
                head = $Receipt.provenance.git.head
                branch = $Receipt.provenance.git.branch
                describe = $Receipt.provenance.git.describe
                status_short = @($Receipt.provenance.git.status_short)
            }
            files = [ordered]@{
                cargo_lock_sha256 = $Receipt.provenance.files.cargo_lock.sha256
                rust_toolchain_sha256 = $Receipt.provenance.files.rust_toolchain.sha256
                release_workflow_sha256 = $Receipt.provenance.files.release_workflow.sha256
                release_verify_script_sha256 = $Receipt.provenance.files.release_verify_script.sha256
            }
            source_trust = [ordered]@{
                schema_version = 1
                signature_format = 'ed25519-detached-hex'
                publisher_public_key_asset = 'publisher-key.ed25519.pub'
                publisher_public_key_sha256_fingerprint = $publisherKeyFingerprint
                signed_assets = @(
                    'SHA256SUMS.txt.sig',
                    'release-provenance.json.sig'
                )
            }
            artifacts = [ordered]@{
                release_binary = [ordered]@{
                    path = 'gh_mirror_gui.exe'
                    size = (Get-Item -LiteralPath $assetExe).Length
                    sha256 = $exeHash
                }
                sha256sums = [ordered]@{
                    path = 'SHA256SUMS.txt'
                    size = (Get-Item -LiteralPath $sha256SumsPath).Length
                    sha256 = $sha256SumsHash
                }
                publisher_public_key = [ordered]@{
                    path = 'publisher-key.ed25519.pub'
                    size = (Get-Item -LiteralPath $publicKeyAsset).Length
                    sha256 = $publisherKeyHash
                    fingerprint_sha256 = $publisherKeyFingerprint
                }
            }
        }
        $provenance | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $provenancePath -Encoding UTF8

        $provenanceSchema = Assert-StagedReleaseProvenance `
            -Path $provenancePath `
            -ExpectedPackageVersion $packageVersion `
            -ExpectedBinarySha256 $exeHash `
            -ExpectedSha256SumsSha256 $sha256SumsHash `
            -ExpectedPublisherKeySha256 $publisherKeyHash `
            -ExpectedPublisherKeyFingerprint $publisherKeyFingerprint

        Invoke-LoggedNative `
            -Name 'signed-release-staging-sign-sha256sums' `
            -Exe $Exe `
            -Arguments @(
                '--sign-verification-source',
                '--source', $sha256SumsPath,
                '--out', $sha256SumsSignaturePath
            )
        Invoke-LoggedNative `
            -Name 'signed-release-staging-sign-provenance' `
            -Exe $Exe `
            -Arguments @(
                '--sign-verification-source',
                '--source', $provenancePath,
                '--out', $provenanceSignaturePath
            )
        $sha256SumsSignature = Assert-UpperHexTextFile -Path $sha256SumsSignaturePath -ExpectedChars 128 -Label 'signed release staging SHA256SUMS signature'
        $provenanceSignature = Assert-UpperHexTextFile -Path $provenanceSignaturePath -ExpectedChars 128 -Label 'signed release staging provenance signature'

        Invoke-LoggedNative `
            -Name 'signed-release-staging-verify-sha256sums' `
            -Exe $Exe `
            -Arguments @(
                '--verify-verification-source',
                '--source', $sha256SumsPath,
                '--signature', $sha256SumsSignaturePath,
                '--public-key-file', $publicKeyAsset,
                '--json', $sha256SumsVerifyJson
            )
        Invoke-LoggedNative `
            -Name 'signed-release-staging-verify-provenance' `
            -Exe $Exe `
            -Arguments @(
                '--verify-verification-source',
                '--source', $provenancePath,
                '--signature', $provenanceSignaturePath,
                '--public-key-file', $publicKeyAsset,
                '--json', $provenanceVerifyJson
            )
        Invoke-LoggedNative `
            -Name 'signed-release-staging-download-selftest' `
            -Exe $Exe `
            -Arguments @(
                '--staged-release-download-selftest',
                '--release-dir', $StageDir,
                '--json', $downloadSelfTestJson
            )
    }
    finally {
        if ($null -eq $oldReleaseKey) {
            Remove-Item Env:RELEASE_ED25519_PRIVATE_KEY_HEX -ErrorAction SilentlyContinue
        }
        else {
            $env:RELEASE_ED25519_PRIVATE_KEY_HEX = $oldReleaseKey
        }
        if ($null -eq $oldLegacyKey) {
            Remove-Item Env:GH_MIRROR_GUI_ED25519_PRIVATE_KEY_HEX -ErrorAction SilentlyContinue
        }
        else {
            $env:GH_MIRROR_GUI_ED25519_PRIVATE_KEY_HEX = $oldLegacyKey
        }
    }

    $sha256SumsVerify = Get-Content -LiteralPath $sha256SumsVerifyJson -Raw | ConvertFrom-Json
    $provenanceVerify = Get-Content -LiteralPath $provenanceVerifyJson -Raw | ConvertFrom-Json
    if (!$sha256SumsVerify.ok) {
        throw 'signed release staging SHA256SUMS signature verification did not report ok=true'
    }
    if (!$provenanceVerify.ok) {
        throw 'signed release staging release-provenance signature verification did not report ok=true'
    }
    if (!(Test-Path -LiteralPath $downloadSelfTestJson)) {
        throw "signed release staging download selftest JSON missing: $downloadSelfTestJson"
    }
    $downloadSelfTest = Get-Content -LiteralPath $downloadSelfTestJson -Raw | ConvertFrom-Json
    if (!$downloadSelfTest.ok) {
        throw 'signed release staging download selftest did not report ok=true'
    }
    if ([string]$downloadSelfTest.download.sha256 -ne [string]$exeHash) {
        throw 'signed release staging download selftest binary hash mismatch'
    }
    if ([string]$downloadSelfTest.verifications.sha256sums.status -ne 'VERIFIED') {
        throw 'signed release staging download selftest did not verify SHA256SUMS.txt'
    }
    if ([string]$downloadSelfTest.verifications.provenance.status -ne 'VERIFIED') {
        throw 'signed release staging download selftest did not verify release-provenance.json'
    }
    if ([string]$downloadSelfTest.verifications.sha256sums.trust_decision -ne 'TRUSTED') {
        throw 'signed release staging download selftest SHA256SUMS trust decision mismatch'
    }
    if ([string]$downloadSelfTest.verifications.provenance.trust_decision -ne 'TRUSTED') {
        throw 'signed release staging download selftest provenance trust decision mismatch'
    }

    $requiredAssetNames = @(
        'gh_mirror_gui.exe',
        'SHA256SUMS.txt',
        'SHA256SUMS.txt.sig',
        'release-provenance.json',
        'release-provenance.json.sig',
        'publisher-key.ed25519.pub'
    )
    $assets = @($requiredAssetNames | ForEach-Object {
        $path = Join-Path $StageDir $_
        if (!(Test-Path -LiteralPath $path)) {
            throw "signed release staging required asset missing: $_"
        }
        [ordered]@{
            name = $_
            path = $path
            size = (Get-Item -LiteralPath $path).Length
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        }
    })

    return [ordered]@{
        ok = $true
        stage_dir = $StageDir
        dry_run = $true
        required_assets = $requiredAssetNames
        assets = $assets
        provenance_schema = $provenanceSchema
        publisher_key = [ordered]@{
            path = $publicKeyAsset
            value = $publisherKeyText
            sha256 = $publisherKeyHash
            fingerprint_sha256 = $publisherKeyFingerprint
        }
        signatures = [ordered]@{
            sha256sums = [ordered]@{
                path = $sha256SumsSignaturePath
                hex_chars = $sha256SumsSignature.Length
            }
            provenance = [ordered]@{
                path = $provenanceSignaturePath
                hex_chars = $provenanceSignature.Length
            }
        }
        verifications = [ordered]@{
            sha256sums = $sha256SumsVerify
            provenance = $provenanceVerify
        }
        download_selftest = $downloadSelfTest
        covered_by = Assert-CommandLogContains `
            -CommandName 'cargo-test-all-targets' `
            -RequiredPatterns @(
                'verify_verification_source_cli_accepts_publisher_key_file',
                'verify_verification_source_cli_rejects_bad_signature',
                'staged_request_contract_allows_missing_best_effort_head_probe',
                'staged_request_contract_requires_deterministic_range_probe',
                'staged_release_download_selftest_downloads_verifies_and_writes_evidence'
            )
    }
}

function Invoke-GitHubLatestRelease {
    param([string]$Repo)

    try {
        $release = Invoke-GitHubApiJson `
            -Name "latest-$Repo" `
            -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -GhPath "repos/$Repo/releases/latest"

        return [ordered]@{
            found = $true
            repo = $Repo
            tag_name = $release.tag_name
            name = $release.name
            published_at = $release.published_at
            html_url = $release.html_url
            body = $release.body
            assets = @($release.assets | ForEach-Object {
                $digest = if ($_.PSObject.Properties.Name -contains 'digest') { $_.digest } else { $null }
                $contentType = if ($_.PSObject.Properties.Name -contains 'content_type') { $_.content_type } else { $null }
                [ordered]@{
                    name = $_.name
                    size = $_.size
                    content_type = $contentType
                    digest = $digest
                    api_url = if ($_.PSObject.Properties.Name -contains 'url') { $_.url } else { $null }
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

function Get-GitHubAccessToken {
    if (![string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
        return [string]$env:GITHUB_TOKEN
    }
    if (![string]::IsNullOrWhiteSpace($env:GH_TOKEN)) {
        return [string]$env:GH_TOKEN
    }

    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if ($null -eq $gh) {
        return $null
    }

    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $tokenLines = & gh auth token 2>$null
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        if ($exitCode -ne 0) {
            return $null
        }
        $token = @($tokenLines | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ }) | Select-Object -First 1
        if ([string]::IsNullOrWhiteSpace($token)) {
            return $null
        }
        return [string]$token
    }
    finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
}

function Invoke-GitHubApiJson {
    param(
        [string]$Name,
        [string]$Uri,
        [string]$GhPath,
        [int]$MaxAttempts = 5,
        [int]$BaseDelaySeconds = 2
    )

    $token = Get-GitHubAccessToken
    $headers = @{
        'User-Agent' = 'gh_mirror_gui-release-verify'
        'Accept'     = 'application/vnd.github+json'
    }
    if (![string]::IsNullOrWhiteSpace($token)) {
        $headers.Authorization = "Bearer $token"
    }

    $attempt = 1
    $errors = @()
    while ($attempt -le $MaxAttempts) {
        try {
            return Invoke-RestMethod `
                -Headers $headers `
                -Uri $Uri `
                -TimeoutSec 60 `
                -ErrorAction Stop
        }
        catch {
            $status = $null
            try {
                if ($_.Exception.Response) {
                    $status = [int]$_.Exception.Response.StatusCode
                }
            }
            catch {
                $status = $null
            }

            $errors += [ordered]@{
                transport = 'Invoke-RestMethod'
                attempt = $attempt
                status_code = $status
                error = $_.Exception.Message
            }

            $transient = @($null, 408, 425, 429, 500, 502, 503, 504)
            $isTransient = ($transient -contains $status)
            if (!$isTransient -or $attempt -ge $MaxAttempts) {
                break
            }

            $delay = [int]([Math]::Min(30, $BaseDelaySeconds * [Math]::Pow(2, ($attempt - 1))))
            Start-Sleep -Seconds $delay
            $attempt += 1
        }
    }

    # `gh api` uses the same GitHub host and the user's official gh auth store,
    # but it is independent of PowerShell WebRequest transport/proxy drift. Keep
    # this inside the single release-verify front door instead of creating a
    # second external gate.
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        try {
            $safeName = ($Name -replace '[^A-Za-z0-9_.-]', '-')
            $jsonLines = @(Invoke-CapturedNative `
                -Name "github-api-$safeName-gh-fallback" `
                -Exe 'gh' `
                -Arguments @('api', $GhPath))
            $json = ($jsonLines -join "`n").Trim()
            if (![string]::IsNullOrWhiteSpace($json)) {
                return ($json | ConvertFrom-Json)
            }
            throw 'gh api returned an empty response'
        }
        catch {
            $errors += [ordered]@{
                transport = 'gh api'
                attempt = 1
                status_code = $null
                error = $_.Exception.Message
            }
        }
    }

    $errorSummary = @($errors | ForEach-Object {
        "$($_.transport)#$($_.attempt) status=$($_.status_code) error=$($_.error)"
    }) -join '; '
    throw "GitHub API $Name failed: $errorSummary"
}

function Convert-GitHubApiReleaseToReceiptShape {
    param(
        [object]$Release,
        [string]$Repo
    )

    return [ordered]@{
        repo = $Repo
        tag_name = $Release.tag_name
        name = $Release.name
        created_at = if ($Release.PSObject.Properties.Name -contains 'created_at') { $Release.created_at } else { $null }
        published_at = $Release.published_at
        html_url = $Release.html_url
        draft = if ($Release.PSObject.Properties.Name -contains 'draft') { [bool]$Release.draft } else { $false }
        prerelease = if ($Release.PSObject.Properties.Name -contains 'prerelease') { [bool]$Release.prerelease } else { $false }
        body = $Release.body
        assets = @($Release.assets | ForEach-Object {
            $digest = if ($_.PSObject.Properties.Name -contains 'digest') { $_.digest } else { $null }
            $contentType = if ($_.PSObject.Properties.Name -contains 'content_type') { $_.content_type } else { $null }
            [ordered]@{
                name = $_.name
                size = $_.size
                content_type = $contentType
                digest = $digest
                api_url = if ($_.PSObject.Properties.Name -contains 'url') { $_.url } else { $null }
                browser_download_url = $_.browser_download_url
            }
        })
    }
}

function Invoke-GitHubPublishedReleases {
    param(
        [string]$Repo,
        [int]$PerPage = 10
    )

    try {
        $raw = Invoke-GitHubApiJson `
            -Name "published-$Repo" `
            -Uri "https://api.github.com/repos/$Repo/releases?per_page=$PerPage" `
            -GhPath "repos/$Repo/releases?per_page=$PerPage"

        $published = @(
            $raw |
                Where-Object { !$_.draft -and !$_.prerelease -and ![string]::IsNullOrWhiteSpace([string]$_.published_at) } |
                ForEach-Object { Convert-GitHubApiReleaseToReceiptShape -Release $_ -Repo $Repo }
        )

        # Keep a deterministic order aligned with GitHub's "latest release" semantics.
        # GitHub defines "latest release" as the most recent non-draft, non-prerelease
        # release sorted by `created_at` (not published_at). So we prefer created_at
        # when present, then published_at.
        $sorted = @(
            $published |
                Sort-Object {
                    if (![string]::IsNullOrWhiteSpace([string]$_.created_at)) {
                        [DateTime]::Parse([string]$_.created_at)
                    }
                    elseif (![string]::IsNullOrWhiteSpace([string]$_.published_at)) {
                        [DateTime]::Parse([string]$_.published_at)
                    }
                    else {
                        [DateTime]::MinValue
                    }
                } -Descending
        )

        return [ordered]@{
            ok = $true
            repo = $Repo
            count = $sorted.Count
            releases = $sorted
        }
    }
    catch {
        $status = $null
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
        }
        return [ordered]@{
            ok = $false
            repo = $Repo
            status_code = $status
            error = $_.Exception.Message
            count = 0
            releases = @()
        }
    }
}

function Get-ReleaseAssetByName {
    param(
        [object]$Release,
        [string]$Name
    )

    $matches = @($Release.assets | Where-Object { $_.name -eq $Name })
    if ($matches.Count -eq 0) {
        return $null
    }
    return $matches[0]
}

function Invoke-WebRequestWithRetry {
    param(
        [string]$Uri,
        [hashtable]$Headers,
        [string]$OutFile,
        [int]$MaxAttempts = 5,
        [int]$BaseDelaySeconds = 2,
        [int]$TimeoutSeconds = 45
    )

    $attempt = 1
    while ($true) {
        try {
            if (![string]::IsNullOrWhiteSpace($OutFile) -and (Test-Path -LiteralPath $OutFile)) {
                Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            }
            Invoke-WebRequest `
                -Uri $Uri `
                -Headers $Headers `
                -MaximumRedirection 10 `
                -TimeoutSec $TimeoutSeconds `
                -OutFile $OutFile `
                -UseBasicParsing | Out-Null
            return [ordered]@{
                ok = $true
                attempts = $attempt
                timeout_seconds = $TimeoutSeconds
            }
        }
        catch {
            $status = $null
            try {
                if ($_.Exception.Response) {
                    $status = [int]$_.Exception.Response.StatusCode
                }
            }
            catch {
                $status = $null
            }

            $transient = @($null, 408, 425, 429, 500, 502, 503, 504)
            $isTransient = ($transient -contains $status)
            if (!$isTransient -or $attempt -ge $MaxAttempts) {
                throw
            }

            $delay = [int]([Math]::Min(30, $BaseDelaySeconds * [Math]::Pow(2, ($attempt - 1))))
            Start-Sleep -Seconds $delay
            $attempt += 1
        }
    }
}

function Save-HttpRangeWithRetry {
    param(
        [string]$Uri,
        [string]$OutFile,
        [int]$Start = 0,
        [int]$End = 65535,
        [int]$MaxAttempts = 2,
        [int]$BaseDelaySeconds = 2,
        [int]$TimeoutSeconds = 60
    )

    Add-Type -AssemblyName System.Net.Http | Out-Null
    $attempt = 1
    $errors = @()
    while ($attempt -le $MaxAttempts) {
        $handler = $null
        $client = $null
        $request = $null
        $response = $null
        $stream = $null
        $file = $null
        try {
            if (![string]::IsNullOrWhiteSpace($OutFile) -and (Test-Path -LiteralPath $OutFile)) {
                Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            }
            $outDir = Split-Path -Parent $OutFile
            if (![string]::IsNullOrWhiteSpace($outDir)) {
                New-Item -ItemType Directory -Force -Path $outDir | Out-Null
            }

            $handler = [System.Net.Http.HttpClientHandler]::new()
            $handler.AllowAutoRedirect = $true
            $client = [System.Net.Http.HttpClient]::new($handler)
            $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
            $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Uri)
            $request.Headers.UserAgent.ParseAdd('gh_mirror_gui-release-verify')
            $request.Headers.Range = [System.Net.Http.Headers.RangeHeaderValue]::new($Start, $End)

            $response = $client.SendAsync(
                $request,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
            ).GetAwaiter().GetResult()
            if (!$response.IsSuccessStatusCode) {
                throw "HTTP status $([int]$response.StatusCode) $($response.ReasonPhrase)"
            }

            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $file = [System.IO.File]::Open(
                $OutFile,
                [System.IO.FileMode]::Create,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None
            )
            $stream.CopyTo($file)

            $contentRange = $null
            if ($null -ne $response.Content.Headers.ContentRange) {
                $contentRange = $response.Content.Headers.ContentRange.ToString()
            }
            $contentLength = $null
            if ($null -ne $response.Content.Headers.ContentLength) {
                $contentLength = [int64]$response.Content.Headers.ContentLength
            }
            $finalUri = $null
            if ($null -ne $response.RequestMessage -and $null -ne $response.RequestMessage.RequestUri) {
                $finalUri = $response.RequestMessage.RequestUri.AbsoluteUri
            }

            return [ordered]@{
                ok = $true
                attempts = $attempt
                status_code = [int]$response.StatusCode
                timeout_seconds = $TimeoutSeconds
                content_range = $contentRange
                content_length = $contentLength
                final_uri = $finalUri
            }
        }
        catch {
            $errors += "attempt=$attempt error=$($_.Exception.Message)"
            if ($attempt -ge $MaxAttempts) {
                throw "HttpClient range request failed: $($errors -join '; ')"
            }
            $delay = [int]([Math]::Min(30, $BaseDelaySeconds * [Math]::Pow(2, ($attempt - 1))))
            Start-Sleep -Seconds $delay
            $attempt += 1
        }
        finally {
            if ($null -ne $file) { $file.Dispose() }
            if ($null -ne $stream) { $stream.Dispose() }
            if ($null -ne $response) { $response.Dispose() }
            if ($null -ne $request) { $request.Dispose() }
            if ($null -ne $client) { $client.Dispose() }
            if ($null -ne $handler) { $handler.Dispose() }
        }
    }
}

function Save-ReleaseAssetWithGhFallback {
    param(
        [object]$Asset,
        [string]$OutFile,
        [int]$MaxAttempts = 4,
        [int]$BaseDelaySeconds = 3
    )

    if (!(Get-Command gh -ErrorAction SilentlyContinue)) {
        throw 'gh CLI not available for release asset fallback'
    }

    $downloadUrl = [string]$Asset.browser_download_url
    if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
        throw 'asset has no browser_download_url for gh release download fallback'
    }
    if ($downloadUrl -notmatch '^https://github\.com/([^/]+)/([^/]+)/releases/download/([^/]+)/(.+)$') {
        throw "asset browser_download_url is not a GitHub release asset URL: $downloadUrl"
    }

    $repo = "$($Matches[1])/$($Matches[2])"
    $tag = [Uri]::UnescapeDataString($Matches[3])
    $assetName = [string]$Asset.name
    $outDir = Split-Path -Parent $OutFile
    if ([string]::IsNullOrWhiteSpace($outDir)) {
        $outDir = '.'
    }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    if (Test-Path -LiteralPath $OutFile) {
        Remove-Item -LiteralPath $OutFile -Force
    }

    $safeName = ("$repo-$tag-$assetName" -replace '[^A-Za-z0-9_.-]', '-')
    $errors = @()
    $attempt = 1
    while ($attempt -le $MaxAttempts) {
        try {
            Invoke-LoggedNative `
                -Name "gh-release-download-$safeName-a$attempt" `
                -Exe 'gh' `
                -Arguments @(
                    'release',
                    'download',
                    $tag,
                    '--repo',
                    $repo,
                    '--pattern',
                    $assetName,
                    '--dir',
                    $outDir,
                    '--clobber'
                )
            break
        }
        catch {
            $errors += "attempt=$attempt error=$($_.Exception.Message)"
            if ($attempt -ge $MaxAttempts) {
                throw "gh release download failed after $MaxAttempts attempts: $($errors -join '; ')"
            }
            $delay = [int]([Math]::Min(30, $BaseDelaySeconds * [Math]::Pow(2, ($attempt - 1))))
            Start-Sleep -Seconds $delay
            $attempt += 1
        }
    }

    $downloadedPath = Join-Path $outDir $assetName
    if (!(Test-Path -LiteralPath $downloadedPath)) {
        throw "gh release download did not create expected asset: $downloadedPath"
    }
    if ($downloadedPath -ne $OutFile) {
        Move-Item -LiteralPath $downloadedPath -Destination $OutFile -Force
    }

    return [ordered]@{
        ok = $true
        transport = 'gh release download'
        repo = $repo
        tag = $tag
        asset = $assetName
        attempts = $attempt
        previous_errors = $errors
    }
}

function Save-ReleaseAsset {
    param(
        [object]$Asset,
        [string]$OutFile
    )

    $token = Get-GitHubAccessToken
    $headers = @{
        'User-Agent' = 'gh_mirror_gui-release-verify'
    }
    if (![string]::IsNullOrWhiteSpace($token)) {
        $headers.Authorization = "Bearer $token"
    }

    $apiUrl = $null
    if ($Asset -is [System.Collections.IDictionary]) {
        if ($Asset.Contains('api_url') -and ![string]::IsNullOrWhiteSpace([string]$Asset['api_url'])) {
            $apiUrl = [string]$Asset['api_url']
        }
    }
    elseif ($Asset.PSObject.Properties.Name -contains 'api_url') {
        $apiUrl = [string]$Asset.api_url
    }

    $transport = [ordered]@{
        ok = $true
        transport = 'Invoke-WebRequest'
    }
    $webRequestMaxAttempts = if (Get-Command gh -ErrorAction SilentlyContinue) { 2 } else { 5 }
    try {
        if (![string]::IsNullOrWhiteSpace($apiUrl)) {
            $apiHeaders = @{
                'User-Agent' = $headers.'User-Agent'
                'Accept'     = 'application/octet-stream'
            }
            if ($headers.ContainsKey('Authorization')) {
                $apiHeaders.Authorization = $headers.Authorization
            }
            $webResult = Invoke-WebRequestWithRetry -Uri $apiUrl -Headers $apiHeaders -OutFile $OutFile -MaxAttempts $webRequestMaxAttempts
        }
        else {
            $webResult = Invoke-WebRequestWithRetry -Uri $Asset.browser_download_url -Headers $headers -OutFile $OutFile -MaxAttempts $webRequestMaxAttempts
        }
        $transport['attempts'] = $webResult.attempts
        $transport['timeout_seconds'] = $webResult.timeout_seconds
    }
    catch {
        $webRequestError = $_.Exception.Message
        try {
            $transport = Save-ReleaseAssetWithGhFallback -Asset $Asset -OutFile $OutFile
            $transport['web_request_error'] = $webRequestError
        }
        catch {
            throw "asset download failed via Invoke-WebRequest ($webRequestError) and gh fallback ($($_.Exception.Message))"
        }
    }

    return [ordered]@{
        path = $OutFile
        size = (Get-Item -LiteralPath $OutFile).Length
        sha256 = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash
        transport = $transport
    }
}

function Invoke-OriginReleaseVerificationSmoke {
    param(
        [object]$Release,
        [string]$Exe
    )

    if (!$Release.found) {
        throw "origin latest release lookup failed: $($Release.error)"
    }

    $binaryAsset = Get-ReleaseAssetByName -Release $Release -Name 'gh_mirror_gui.exe'
    $checksumAsset = Get-ReleaseAssetByName -Release $Release -Name 'SHA256SUMS.txt'
    $checksumSignatureAsset = Get-ReleaseAssetByName -Release $Release -Name 'SHA256SUMS.txt.sig'
    $provenanceAsset = Get-ReleaseAssetByName -Release $Release -Name 'release-provenance.json'
    $provenanceSignatureAsset = Get-ReleaseAssetByName -Release $Release -Name 'release-provenance.json.sig'
    $publisherKeyAsset = Get-ReleaseAssetByName -Release $Release -Name 'publisher-key.ed25519.pub'
    if ($null -eq $binaryAsset) {
        throw "origin release $($Release.tag_name) missing gh_mirror_gui.exe"
    }
    if ($null -eq $checksumAsset) {
        throw "origin release $($Release.tag_name) missing SHA256SUMS.txt"
    }
    if ($null -eq $checksumSignatureAsset) {
        throw "origin release $($Release.tag_name) missing SHA256SUMS.txt.sig"
    }
    if ($null -eq $provenanceAsset) {
        throw "origin release $($Release.tag_name) missing release-provenance.json"
    }
    if ($null -eq $provenanceSignatureAsset) {
        throw "origin release $($Release.tag_name) missing release-provenance.json.sig"
    }
    if ($null -eq $publisherKeyAsset) {
        throw "origin release $($Release.tag_name) missing publisher-key.ed25519.pub"
    }

    $assetDir = Join-Path $EvidenceDir 'origin-release-verification'
    New-Item -ItemType Directory -Force -Path $assetDir | Out-Null
    $checksumPath = Join-Path $assetDir $checksumAsset.name
    $checksumSignaturePath = Join-Path $assetDir $checksumSignatureAsset.name
    $provenancePath = Join-Path $assetDir $provenanceAsset.name
    $provenanceSignaturePath = Join-Path $assetDir $provenanceSignatureAsset.name
    $publisherKeyPath = Join-Path $assetDir $publisherKeyAsset.name
    $checksumEvidence = Save-ReleaseAsset -Asset $checksumAsset -OutFile $checksumPath
    $checksumSignatureEvidence = Save-ReleaseAsset -Asset $checksumSignatureAsset -OutFile $checksumSignaturePath
    $provenanceEvidence = Save-ReleaseAsset -Asset $provenanceAsset -OutFile $provenancePath
    $provenanceSignatureEvidence = Save-ReleaseAsset -Asset $provenanceSignatureAsset -OutFile $provenanceSignaturePath
    $publisherKeyEvidence = Save-ReleaseAsset -Asset $publisherKeyAsset -OutFile $publisherKeyPath

    $checksumText = Get-Content -LiteralPath $checksumPath -Raw
    $checksumLine = @($checksumText -split "`r?`n" | Where-Object {
        $_ -match '^\s*([A-Fa-f0-9]{64})\s+\*?(\./)?gh_mirror_gui\.exe\s*$'
    } | Select-Object -First 1)
    if ($checksumLine.Count -eq 0) {
        throw "SHA256SUMS.txt did not contain gh_mirror_gui.exe SHA256"
    }
    $expectedHash = ([regex]::Match($checksumLine[0], '([A-Fa-f0-9]{64})').Groups[1].Value).ToUpperInvariant()

    $provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
    $provenanceAssetPath = [string]$provenance.artifacts.release_binary.path
    $provenanceHash = ([string]$provenance.artifacts.release_binary.sha256).ToUpperInvariant()
    $provenancePublisherFingerprint = ([string]$provenance.source_trust.publisher_public_key_sha256_fingerprint).ToUpperInvariant()
    if ($provenanceAssetPath -ne 'gh_mirror_gui.exe') {
        throw "release-provenance.json release_binary.path mismatch: $provenanceAssetPath"
    }
    if ($provenanceHash -ne $expectedHash) {
        throw "release-provenance.json binary hash $provenanceHash does not match SHA256SUMS.txt $expectedHash"
    }

    $binaryDigestHash = $null
    if ($binaryAsset.digest) {
        $binaryDigestHash = ([string]$binaryAsset.digest -replace '^sha256:', '').ToUpperInvariant()
        if ($binaryDigestHash -ne $expectedHash) {
            throw "GitHub asset digest $binaryDigestHash does not match SHA256SUMS.txt $expectedHash"
        }
    }

    $checksumVerifyJson = Join-Path $assetDir 'verify-SHA256SUMS.txt.json'
    Invoke-LoggedNative `
        -Name 'origin-verify-sha256sums-signature' `
        -Exe $Exe `
        -Arguments @(
            '--verify-verification-source',
            '--source', $checksumPath,
            '--signature', $checksumSignaturePath,
            '--public-key-file', $publisherKeyPath,
            '--json', $checksumVerifyJson
        )
    $provenanceVerifyJson = Join-Path $assetDir 'verify-release-provenance.json'
    Invoke-LoggedNative `
        -Name 'origin-verify-provenance-signature' `
        -Exe $Exe `
        -Arguments @(
            '--verify-verification-source',
            '--source', $provenancePath,
            '--signature', $provenanceSignaturePath,
            '--public-key-file', $publisherKeyPath,
            '--json', $provenanceVerifyJson
        )
    if (!(Test-Path -LiteralPath $checksumVerifyJson)) {
        throw "origin SHA256SUMS signature verification JSON missing: $checksumVerifyJson"
    }
    if (!(Test-Path -LiteralPath $provenanceVerifyJson)) {
        throw "origin provenance signature verification JSON missing: $provenanceVerifyJson"
    }
    $checksumSignatureVerification = Get-Content -LiteralPath $checksumVerifyJson -Raw | ConvertFrom-Json
    $provenanceSignatureVerification = Get-Content -LiteralPath $provenanceVerifyJson -Raw | ConvertFrom-Json
    if (!$checksumSignatureVerification.ok -or !$checksumSignatureVerification.signature.verified) {
        throw 'origin SHA256SUMS.txt detached signature did not verify'
    }
    if (!$provenanceSignatureVerification.ok -or !$provenanceSignatureVerification.signature.verified) {
        throw 'origin release-provenance.json detached signature did not verify'
    }
    $checksumPublisherFingerprint = ([string]$checksumSignatureVerification.public_key.fingerprint_sha256).ToUpperInvariant()
    $provenanceVerifiedFingerprint = ([string]$provenanceSignatureVerification.public_key.fingerprint_sha256).ToUpperInvariant()
    if ($checksumPublisherFingerprint -notmatch '^[0-9A-F]{64}$') {
        throw "origin publisher key fingerprint from SHA256SUMS verification was invalid: $checksumPublisherFingerprint"
    }
    if ($provenanceVerifiedFingerprint -ne $checksumPublisherFingerprint) {
        throw "origin signature verification fingerprint mismatch: SHA256SUMS=$checksumPublisherFingerprint provenance=$provenanceVerifiedFingerprint"
    }
    if ($provenancePublisherFingerprint -ne $checksumPublisherFingerprint) {
        throw "origin release-provenance.json publisher fingerprint $provenancePublisherFingerprint does not match verified public key $checksumPublisherFingerprint"
    }

    return [ordered]@{
        ok = $true
        repo = $Release.repo
        tag_name = $Release.tag_name
        html_url = $Release.html_url
        binary_asset = [ordered]@{
            name = $binaryAsset.name
            size = $binaryAsset.size
            digest = $binaryAsset.digest
        }
        checksum_asset = [ordered]@{
            name = $checksumAsset.name
            size = $checksumAsset.size
            downloaded = $checksumEvidence
        }
        checksum_signature_asset = [ordered]@{
            name = $checksumSignatureAsset.name
            size = $checksumSignatureAsset.size
            digest = $checksumSignatureAsset.digest
            downloaded = $checksumSignatureEvidence
        }
        provenance_asset = [ordered]@{
            name = $provenanceAsset.name
            size = $provenanceAsset.size
            downloaded = $provenanceEvidence
        }
        provenance_signature_asset = [ordered]@{
            name = $provenanceSignatureAsset.name
            size = $provenanceSignatureAsset.size
            digest = $provenanceSignatureAsset.digest
            downloaded = $provenanceSignatureEvidence
        }
        publisher_key_asset = [ordered]@{
            name = $publisherKeyAsset.name
            size = $publisherKeyAsset.size
            digest = $publisherKeyAsset.digest
            downloaded = $publisherKeyEvidence
            fingerprint_sha256 = $checksumPublisherFingerprint
        }
        expected_sha256 = $expectedHash
        provenance_release_tag = $provenance.release_tag
        provenance_package_version = $provenance.package_version
        provenance_github_sha = $provenance.github.sha
        github_asset_digest_sha256 = $binaryDigestHash
        source_signature_verification = [ordered]@{
            ok = $true
            publisher_key_fingerprint_sha256 = $checksumPublisherFingerprint
            sha256sums = $checksumSignatureVerification
            provenance = $provenanceSignatureVerification
        }
    }
}

function Invoke-UpdateCandidateContractSelfTest {
    param(
        [string]$Exe,
        [string]$JsonFile
    )

    Invoke-LoggedNative `
        -Name 'update-candidate-contract-selftest' `
        -Exe $Exe `
        -Arguments @(
            '--update-candidate-contract-selftest',
            '--json', $JsonFile
        )
    if (!(Test-Path -LiteralPath $JsonFile)) {
        throw "update candidate contract selftest JSON missing: $JsonFile"
    }
    $selftest = Get-Content -LiteralPath $JsonFile -Raw | ConvertFrom-Json
    if (!$selftest.ok) {
        throw 'update candidate contract selftest did not report ok=true'
    }
    if (!$selftest.no_mutation) {
        throw 'update candidate contract selftest must be no-mutation'
    }
    $cases = @($selftest.cases)
    $required = [ordered]@{
        newer_trusted_candidate = 'CANDIDATE'
        same_version_no_update = 'NO_UPDATE'
        bad_signature_refused = 'REFUSED'
        missing_key_refused = 'REFUSED'
        unsigned_required_refused = 'REFUSED'
    }
    foreach ($name in $required.Keys) {
        $case = @($cases | Where-Object { [string]$_.name -eq $name } | Select-Object -First 1)
        if ($case.Count -eq 0) {
            throw "update candidate contract selftest missing case: $name"
        }
        $status = [string]$case[0].status
        if ($status -ne [string]$required[$name]) {
            throw "update candidate contract selftest case $name status $status did not match $($required[$name])"
        }
    }

    return $selftest
}

function Invoke-UpdateApplyPlanContractSelfTest {
    param(
        [string]$Exe,
        [string]$JsonFile
    )

    Invoke-LoggedNative `
        -Name 'update-apply-plan-contract-selftest' `
        -Exe $Exe `
        -Arguments @(
            '--update-apply-plan-contract-selftest',
            '--json', $JsonFile
        )
    if (!(Test-Path -LiteralPath $JsonFile)) {
        throw "update apply plan contract selftest JSON missing: $JsonFile"
    }
    $selftest = Get-Content -LiteralPath $JsonFile -Raw | ConvertFrom-Json
    if (!$selftest.ok) {
        throw 'update apply plan contract selftest did not report ok=true'
    }
    if (!$selftest.no_mutation) {
        throw 'update apply plan contract selftest must be no-mutation'
    }
    if (!$selftest.reversible) {
        throw 'update apply plan contract selftest must be reversible'
    }
    if ([string]$selftest.status -ne 'PLANNED') {
        throw "update apply plan contract selftest status $($selftest.status) was not PLANNED"
    }
    if (!$selftest.evidence.ready) {
        throw 'update apply plan contract selftest did not write an evidence file'
    }
    if (!$selftest.evidence.record.ok) {
        throw 'update apply plan contract selftest evidence record did not report ok=true'
    }

    return $selftest
}

function Invoke-UpdateCandidateLatestSelfTest {
    param(
        [string]$Exe,
        [string]$JsonFile
    )

    Invoke-LoggedNative `
        -Name 'update-candidate-latest-selftest' `
        -Exe $Exe `
        -Arguments @(
            '--update-candidate-latest-selftest',
            '--json', $JsonFile
        )
    if (!(Test-Path -LiteralPath $JsonFile)) {
        throw "update candidate latest selftest JSON missing: $JsonFile"
    }
    $selftest = Get-Content -LiteralPath $JsonFile -Raw | ConvertFrom-Json
    if (!$selftest.ok) {
        throw 'update candidate latest selftest did not report ok=true'
    }
    if (!$selftest.no_mutation) {
        throw 'update candidate latest selftest must be no-mutation'
    }
    if (!$selftest.evidence_ready) {
        throw 'update candidate latest selftest evidence path was not ready'
    }
    $allowed = @('CANDIDATE', 'NO_UPDATE', 'REFUSED')
    if ($allowed -notcontains [string]$selftest.status) {
        throw "update candidate latest selftest status $($selftest.status) was not allowed"
    }
    if ([string]$selftest.report.release_tag -eq 'unknown') {
        throw 'update candidate latest selftest did not resolve a live latest release'
    }
    if (!$selftest.report.evaluation.no_mutation) {
        throw 'update candidate latest report evaluation must be no-mutation'
    }
    if ([string]$selftest.report.evaluation.status -ne [string]$selftest.status) {
        throw 'update candidate latest status mismatch between wrapper and report'
    }

    return $selftest
}

function Invoke-UpdateCandidateStageSelfTest {
    param(
        [string]$Exe,
        [string]$JsonFile
    )

    Invoke-LoggedNative `
        -Name 'update-candidate-stage-selftest' `
        -Exe $Exe `
        -Arguments @(
            '--update-candidate-stage-selftest',
            '--json', $JsonFile
        )
    if (!(Test-Path -LiteralPath $JsonFile)) {
        throw "update candidate stage selftest JSON missing: $JsonFile"
    }
    $selftest = Get-Content -LiteralPath $JsonFile -Raw | ConvertFrom-Json
    if (!$selftest.ok) {
        throw 'update candidate stage selftest did not report ok=true'
    }
    if (!$selftest.no_mutation) {
        throw 'update candidate stage selftest must be no-mutation'
    }
    if (!$selftest.no_install) {
        throw 'update candidate stage selftest must be no-install'
    }
    if (!$selftest.check_evidence_ready) {
        throw 'update candidate stage selftest check evidence path was not ready'
    }
    if (!$selftest.stage_evidence_ready) {
        throw 'update candidate stage selftest stage evidence was not ready'
    }
    $allowed = @('STAGED', 'NO_UPDATE', 'REFUSED')
    if ($allowed -notcontains [string]$selftest.status) {
        throw "update candidate stage selftest status $($selftest.status) was not allowed"
    }
    if ([string]$selftest.report.release_tag -eq 'unknown') {
        throw 'update candidate stage selftest did not resolve a live latest release'
    }
    if (!$selftest.report.no_install) {
        throw 'update candidate stage report must be no-install'
    }
    if (!$selftest.report.check_report.evaluation.no_mutation) {
        throw 'update candidate stage report evaluation must be no-mutation'
    }

    return $selftest
}

function Invoke-PostPublishSelfUpdateStage2Check {
    param(
        [string]$Repo,
        [string]$ExpectedLatestTag,
        [string]$Exe
    )

    $dir = Join-Path $EvidenceDir 'post-publish-self-update-stage2'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $releaseList = Invoke-GitHubPublishedReleases -Repo $Repo -PerPage 10
    if (!$releaseList.ok) {
        throw "post-publish self-update Stage 2 release list failed: HTTP $($releaseList.status_code) $($releaseList.error)"
    }
    $releases = @($releaseList.releases)
    if ($releases.Count -lt 2) {
        throw "post-publish self-update Stage 2 requires at least 2 published releases; got $($releases.Count)"
    }

    $latest = $null
    if (![string]::IsNullOrWhiteSpace($ExpectedLatestTag)) {
        $latest = @($releases | Where-Object { $_.tag_name -eq $ExpectedLatestTag } | Select-Object -First 1)[0]
    }
    if ($null -eq $latest) {
        $latest = $releases[0]
    }
    $previous = @($releases | Where-Object { $_.tag_name -ne $latest.tag_name } | Select-Object -First 1)[0]
    if ($null -eq $previous) {
        throw "post-publish self-update Stage 2 could not determine the previous published release for $Repo"
    }

    $publisherKeyAsset = Get-ReleaseAssetByName -Release $latest -Name 'publisher-key.ed25519.pub'
    if ($null -eq $publisherKeyAsset) {
        throw "post-publish self-update Stage 2 latest release $($latest.tag_name) missing publisher-key.ed25519.pub"
    }

    if ([string]::IsNullOrWhiteSpace($Exe) -or !(Test-Path -LiteralPath $Exe)) {
        throw "post-publish self-update Stage 2 requires a local built gh_mirror_gui.exe to run selftests: $Exe"
    }

    $publisherKeyPath = Join-Path $dir "publisher-key.ed25519.pub"
    $publisherKeyEvidence = Save-ReleaseAsset -Asset $publisherKeyAsset -OutFile $publisherKeyPath

    $json = Join-Path $dir 'update-candidate-stage-selftest.json'
    Invoke-LoggedNative `
        -Name 'post-publish-self-update-stage2' `
        -Exe $Exe `
        -Arguments @(
            '--update-candidate-stage-selftest',
            '--json', $json,
            '--current-version', $previous.tag_name,
            '--trusted-publisher-key-file', $publisherKeyPath
        )

    if (!(Test-Path -LiteralPath $json)) {
        throw "post-publish self-update Stage 2 stage selftest JSON missing: $json"
    }
    $selftest = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json

    if (!$selftest.ok) {
        throw 'post-publish self-update Stage 2 stage selftest did not report ok=true'
    }
    if (!$selftest.no_mutation) {
        throw 'post-publish self-update Stage 2 must be no-mutation'
    }
    if (!$selftest.no_install) {
        throw 'post-publish self-update Stage 2 must be no-install'
    }
    $allowed = @('STAGED', 'NO_UPDATE')
    if ($allowed -notcontains [string]$selftest.status) {
        throw "post-publish self-update Stage 2 status $($selftest.status) was not allowed"
    }
    if ([string]$selftest.report.release_tag -eq 'unknown') {
        throw 'post-publish self-update Stage 2 did not resolve a live latest release'
    }
    if ([string]$selftest.input.trusted_publisher_key_file -ne $publisherKeyPath) {
        throw 'post-publish self-update Stage 2 did not pass the Release asset publisher key file into the selftest'
    }
    if ([string]$selftest.input.current_version -ne [string]$previous.tag_name) {
        throw 'post-publish self-update Stage 2 did not override current version to the previous release tag'
    }

    $stageDir = [string]$selftest.report.stage_dir
    if ($selftest.status -eq 'STAGED') {
        if ([string]::IsNullOrWhiteSpace($stageDir) -or !(Test-Path -LiteralPath $stageDir)) {
            throw 'post-publish self-update Stage 2 STAGED verdict missing stage_dir'
        }
        if (!$stageDir.StartsWith($dir, [StringComparison]::OrdinalIgnoreCase)) {
            throw "post-publish self-update Stage 2 stage_dir must stay inside evidence dir: $stageDir"
        }
    }

    return [ordered]@{
        ok = $true
        repo = $Repo
        latest_release_tag = [string]$latest.tag_name
        simulated_current_release_tag = [string]$previous.tag_name
        pinned_publisher_key = [ordered]@{
            from_release_tag = [string]$latest.tag_name
            asset = [string]$publisherKeyAsset.name
            downloaded = $publisherKeyEvidence
        }
        runner_binary = [ordered]@{
            path = $Exe
            sha256 = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash
        }
        stage_selftest = $selftest
    }
}

function Invoke-NetworkRangeSmoke {
    param(
        [string]$Url,
        [string]$OutFile
    )

    $errors = @()
    $transport = $null
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        $oldErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $curlOutput = & $curl.Source -L --fail --silent --show-error `
                --connect-timeout 20 `
                --max-time 120 `
                --retry 3 `
                --retry-delay 2 `
                --retry-connrefused `
                --range 0-65535 `
                --user-agent 'gh_mirror_gui-release-verify' `
                --output $OutFile `
                $Url 2>&1
            $curlExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        }
        finally {
            $ErrorActionPreference = $oldErrorActionPreference
        }
        @($curlOutput | ForEach-Object { $_.ToString() }) |
            Set-Content -LiteralPath (Join-Path $EvidenceDir 'network-range-smoke-curl.log') -Encoding UTF8
        if ($curlExitCode -eq 0) {
            $transport = [ordered]@{
                name = 'curl.exe'
                exit_code = $curlExitCode
            }
        }
        else {
            $errors += "curl.exe exit_code=$curlExitCode"
            if (Test-Path -LiteralPath $OutFile) {
                Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            }
        }
    }

    if ($null -eq $transport) {
        try {
            $webResult = Save-HttpRangeWithRetry `
                -Uri $Url `
                -OutFile $OutFile `
                -MaxAttempts 2 `
                -BaseDelaySeconds 2 `
                -TimeoutSeconds 60
            $transport = [ordered]@{
                name = 'HttpClient'
                attempts = $webResult.attempts
                status_code = $webResult.status_code
                timeout_seconds = $webResult.timeout_seconds
                content_range = $webResult.content_range
                content_length = $webResult.content_length
                final_uri = $webResult.final_uri
                fallback_after = $errors
            }
        }
        catch {
            $errors += "Invoke-WebRequest error=$($_.Exception.Message)"
            try {
                $assetName = [Uri]::UnescapeDataString(($Url -split '/')[-1])
                $asset = [pscustomobject]@{
                    browser_download_url = $Url
                    name = $assetName
                }
                $ghResult = Save-ReleaseAssetWithGhFallback -Asset $asset -OutFile $OutFile
                $transport = [ordered]@{
                    name = 'gh release download'
                    degraded_from_range_request = $true
                    repo = $ghResult.repo
                    tag = $ghResult.tag
                    asset = $ghResult.asset
                    fallback_after = $errors
                }
            }
            catch {
                $errors += "gh release download error=$($_.Exception.Message)"
                throw "network range smoke failed: $($errors -join '; ')"
            }
        }
    }

    $item = Get-Item -LiteralPath $OutFile
    return [ordered]@{
        ok = ($item.Length -gt 0)
        url = $Url
        output = $OutFile
        bytes = $item.Length
        sha256 = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash
        transport = $transport
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

function Start-LocalRangeFileServer {
    param(
        [string]$FilePath,
        [string]$RouteName,
        [string]$Name
    )

    $item = Get-Item -LiteralPath $FilePath
    $safeRoute = ($RouteName -replace '[^A-Za-z0-9_.-]', '-')
    if ([string]::IsNullOrWhiteSpace($safeRoute)) {
        $safeRoute = 'asset.bin'
    }
    $safeName = ($Name -replace '[^A-Za-z0-9_.-]', '-')
    if ([string]::IsNullOrWhiteSpace($safeName)) {
        $safeName = 'range-server'
    }

    $portProbe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), 0)
    $portProbe.Start()
    $port = [int]$portProbe.LocalEndpoint.Port
    $portProbe.Stop()

    $baseUrl = "http://127.0.0.1:$port/"
    $stopPath = Join-Path $EvidenceDir "$safeName.stop"
    $logPath = Join-Path $EvidenceDir "$safeName.log"
    Remove-Item -LiteralPath $stopPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue

    $job = Start-Job -Name "gh_mirror_gui-$safeName" -ArgumentList @(
        $item.FullName,
        $baseUrl,
        $safeRoute,
        $stopPath,
        $logPath
    ) -ScriptBlock {
        param(
            [string]$ServerFilePath,
            [string]$ServerBaseUrl,
            [string]$ServerRoute,
            [string]$ServerStopPath,
            [string]$ServerLogPath
        )

        $ErrorActionPreference = 'Stop'
        function Write-RangeServerLog {
            param([string]$Message)
            $line = "{0} {1}" -f (Get-Date).ToString('o'), $Message
            Add-Content -LiteralPath $ServerLogPath -Value $line -Encoding UTF8
        }
        function Write-RangeServerText {
            param(
                [System.Net.HttpListenerContext]$Context,
                [int]$StatusCode,
                [string]$Text
            )
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
            $Context.Response.StatusCode = $StatusCode
            $Context.Response.ContentType = 'text/plain; charset=utf-8'
            $Context.Response.ContentLength64 = $bytes.Length
            if ($Context.Request.HttpMethod -ne 'HEAD') {
                $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            }
        }

        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add($ServerBaseUrl)
        $listener.Start()
        Write-RangeServerLog "STARTED base=$ServerBaseUrl route=$ServerRoute file=$ServerFilePath"
        try {
            $async = $listener.BeginGetContext($null, $null)
            while (!(Test-Path -LiteralPath $ServerStopPath)) {
                if (!$async.AsyncWaitHandle.WaitOne(500)) {
                    continue
                }
                $context = $listener.EndGetContext($async)
                $async = $listener.BeginGetContext($null, $null)
                try {
                    $path = $context.Request.Url.AbsolutePath.TrimStart('/')
                    if ($path -eq '__health') {
                        Write-RangeServerText -Context $context -StatusCode 200 -Text 'OK'
                        continue
                    }
                    if ($path -ne $ServerRoute) {
                        Write-RangeServerText -Context $context -StatusCode 404 -Text 'not found'
                        continue
                    }

                    $fileInfo = Get-Item -LiteralPath $ServerFilePath
                    $total = [int64]$fileInfo.Length
                    $start = [int64]0
                    $end = [int64]($total - 1)
                    $status = 200
                    $range = [string]$context.Request.Headers['Range']
                    if ($range -match '^bytes=(\d+)-(\d*)$') {
                        $start = [int64]$Matches[1]
                        if (![string]::IsNullOrWhiteSpace($Matches[2])) {
                            $end = [int64]$Matches[2]
                        }
                        if ($start -ge $total) {
                            $context.Response.StatusCode = 416
                            $context.Response.Headers.Add('Content-Range', "bytes */$total")
                            $context.Response.ContentLength64 = 0
                            continue
                        }
                        if ($end -ge $total) {
                            $end = [int64]($total - 1)
                        }
                        $status = 206
                    }

                    $count = [int64]($end - $start + 1)
                    $context.Response.StatusCode = $status
                    $context.Response.ContentType = 'application/octet-stream'
                    $context.Response.Headers.Add('Accept-Ranges', 'bytes')
                    $context.Response.Headers.Add('ETag', '"release-verify-local-range"')
                    $context.Response.Headers.Add('Last-Modified', $fileInfo.LastWriteTimeUtc.ToString('R'))
                    if ($status -eq 206) {
                        $context.Response.Headers.Add('Content-Range', "bytes $start-$end/$total")
                    }
                    $context.Response.ContentLength64 = $count

                    if ($context.Request.HttpMethod -ne 'HEAD') {
                        $buffer = New-Object byte[] 1048576
                        $remaining = $count
                        $stream = [System.IO.File]::OpenRead($ServerFilePath)
                        try {
                            [void]$stream.Seek($start, [System.IO.SeekOrigin]::Begin)
                            while ($remaining -gt 0) {
                                $toRead = [int][Math]::Min($buffer.Length, $remaining)
                                $read = $stream.Read($buffer, 0, $toRead)
                                if ($read -le 0) { break }
                                $context.Response.OutputStream.Write($buffer, 0, $read)
                                $remaining -= $read
                            }
                        }
                        finally {
                            if ($null -ne $stream) { $stream.Dispose() }
                        }
                    }
                }
                catch {
                    Write-RangeServerLog "REQUEST_ERROR $($_.Exception.Message)"
                    try {
                        if ($context.Response.OutputStream.CanWrite) {
                            Write-RangeServerText -Context $context -StatusCode 500 -Text 'server error'
                        }
                    }
                    catch {}
                }
                finally {
                    try { $context.Response.Close() } catch {}
                }
            }
        }
        finally {
            Write-RangeServerLog 'STOPPED'
            if ($listener.IsListening) {
                $listener.Stop()
            }
            $listener.Close()
        }
    }

    $healthUrl = "${baseUrl}__health"
    $ready = $false
    for ($i = 0; $i -lt 50; $i++) {
        Start-Sleep -Milliseconds 100
        if ($job.State -eq 'Failed') {
            $jobOutput = Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue
            throw "local range server failed to start: $($jobOutput -join '; ')"
        }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $healthUrl -TimeoutSec 2
            if ([int]$response.StatusCode -eq 200) {
                $ready = $true
                break
            }
        }
        catch {}
    }
    if (!$ready) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        throw "local range server did not become ready at $baseUrl"
    }

    return [ordered]@{
        url = "$baseUrl$safeRoute"
        base_url = $baseUrl
        job_id = $job.Id
        stop_path = $stopPath
        log_path = $logPath
        source = $item.FullName
        source_size = $item.Length
        route = $safeRoute
    }
}

function Stop-LocalRangeFileServer {
    param([object]$Server)

    if ($null -eq $Server) {
        return
    }
    try {
        Set-Content -LiteralPath $Server.stop_path -Value 'stop' -Encoding UTF8
    }
    catch {}
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$($Server.base_url)__health" -TimeoutSec 2 | Out-Null
    }
    catch {}
    $job = Get-Job -Id $Server.job_id -ErrorAction SilentlyContinue
    if ($null -ne $job) {
        Wait-Job -Job $job -Timeout 5 | Out-Null
        $jobOutput = Receive-Job -Job $job -ErrorAction SilentlyContinue
        if ($jobOutput) {
            Add-Content -LiteralPath $Server.log_path -Value $jobOutput -Encoding UTF8
        }
        if ($job.State -eq 'Running') {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-BenchVariant {
    param(
        [string]$Name,
        [string]$Url,
        [string]$OutFile,
        [string]$JsonFile,
        [string[]]$ExtraArgs,
        [int]$MaxAttempts = 3,
        [int]$BaseDelaySeconds = 5
    )

    $errors = @()
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            foreach ($path in @(
                    $OutFile,
                    "$OutFile.part",
                    "$OutFile.part.json",
                    $JsonFile
                )) {
                if (Test-Path -LiteralPath $path) {
                    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
                }
            }

            Invoke-LoggedNative `
                -Name "bench-$Name-a$attempt" `
                -Exe $exe `
                -Arguments (@(
                    '--bench-download',
                    '--url', $Url,
                    '--out', $OutFile,
                    '--json', $JsonFile,
                    '--history', $HistoryPath
                ) + $ExtraArgs)
            break
        }
        catch {
            $errors += "attempt=$attempt error=$($_.Exception.Message)"
            if ($attempt -ge $MaxAttempts) {
                throw "benchmark $Name failed after $MaxAttempts attempts: $($errors -join '; ')"
            }
            $delay = [int]([Math]::Min(45, $BaseDelaySeconds * [Math]::Pow(2, ($attempt - 1))))
            Start-Sleep -Seconds $delay
        }
    }

    $bench = Get-Content -LiteralPath $JsonFile -Raw | ConvertFrom-Json
    if ($bench.status -ne 'PASS') {
        throw "benchmark $Name status was $($bench.status)"
    }
    if ((Get-Item -LiteralPath $OutFile).Length -ne $bench.total_bytes) {
        throw "benchmark $Name size mismatch"
    }
    $bench | Add-Member -NotePropertyName release_verify_attempts -NotePropertyValue $attempt -Force
    $bench | Add-Member -NotePropertyName release_verify_previous_errors -NotePropertyValue $errors -Force
    return $bench
}

function Assert-DesignDocInventory {
    $allowedDocs = @(
        'AGENTS.md',
        'README.md',
        'docs/ROADMAP.md',
        'docs/ARCHITECTURE.md'
    )
    $allowedDocsUnderDocs = @(
        'docs/ARCHITECTURE.md',
        'docs/ROADMAP.md'
    )
    $trackedDocsUnderDocs = @(Invoke-CapturedNative `
        -Name 'tracked-docs-markdown' `
        -Exe 'git' `
        -Arguments @('ls-files', '--', 'docs/*.md', 'docs/**/*.md') |
        ForEach-Object { ([string]$_).Replace('\', '/') } |
        Where-Object { $_.Trim().Length -gt 0 } |
        Sort-Object -Unique)

    $missing = @($allowedDocsUnderDocs | Where-Object { $trackedDocsUnderDocs -notcontains $_ })
    $unexpected = @($trackedDocsUnderDocs | Where-Object { $allowedDocsUnderDocs -notcontains $_ })
    if ($missing.Count -gt 0 -or $unexpected.Count -gt 0) {
        throw "design doc inventory drift. missing=[$($missing -join ', ')] unexpected=[$($unexpected -join ', ')]"
    }

    return [ordered]@{
        ok = $true
        contract = 'design/end-state docs are anchored only in AGENTS.md, README.md, docs/ROADMAP.md, and docs/ARCHITECTURE.md; run/audit evidence belongs in target/delivery receipts or .run namespaces'
        allowed_docs = $allowedDocs
        tracked_docs_under_docs = $trackedDocsUnderDocs
    }
}

function Assert-GoalAnchorContract {
    $relativePath = 'docs\GOAL-ANCHOR.json'
    $path = Join-Path $RepoRoot $relativePath
    if (!(Test-Path -LiteralPath $path)) {
        throw "required goal anchor missing: $relativePath"
    }

    try {
        $anchor = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "required goal anchor is not valid JSON: $($_.Exception.Message)"
    }

    if ([string]$anchor.schema -ne 'gh_mirror_gui.goal_anchor.v1') {
        throw "goal anchor schema mismatch: $($anchor.schema)"
    }
    if ([string]$anchor.authority.anchor_path -ne 'docs/GOAL-ANCHOR.json') {
        throw "goal anchor authority.anchor_path mismatch"
    }

    $designDocs = @($anchor.DESIGN_DOCS | ForEach-Object { [string]$_.path })
    $requiredDesignDocs = @(
        'AGENTS.md',
        'README.md',
        'docs/ROADMAP.md',
        'docs/ARCHITECTURE.md'
    )
    $missingDesignDocs = @($requiredDesignDocs | Where-Object { $designDocs -notcontains $_ })
    if ($missingDesignDocs.Count -gt 0) {
        throw "goal anchor missing DESIGN_DOCS entries: $($missingDesignDocs -join ', ')"
    }

    if ([string]$anchor.RELEASE_GATE.front_door -ne 'tools/release-verify.ps1 + receipt.json') {
        throw "goal anchor RELEASE_GATE.front_door mismatch"
    }
    if ([string]$anchor.RELEASE_GATE.required_status -ne 'PASS') {
        throw "goal anchor RELEASE_GATE.required_status must be PASS"
    }
    if (!$anchor.RELEASE_GATE.single_delivery_judge) {
        throw "goal anchor RELEASE_GATE.single_delivery_judge must be true"
    }

    if ([string]$anchor.RUN_ROOT.namespace_template -ne '.run/<namespace>/{logs,data,cache,tmp}') {
        throw "goal anchor RUN_ROOT.namespace_template mismatch"
    }
    if ([string]$anchor.RUN_ROOT.release_evidence_root -ne 'target/delivery/<run_id>/receipt.json') {
        throw "goal anchor RUN_ROOT.release_evidence_root mismatch"
    }

    $executeGateIds = @($anchor.EXECUTE_GATES.must_gate | ForEach-Object { [string]$_.id })
    $requiredExecuteGates = @(
        'installer_or_unknown_binary',
        'publish_or_release_mutation',
        'real_network',
        'system_level_change',
        'destructive_delete'
    )
    $missingExecuteGates = @($requiredExecuteGates | Where-Object { $executeGateIds -notcontains $_ })
    if ($missingExecuteGates.Count -gt 0) {
        throw "goal anchor missing EXECUTE_GATES entries: $($missingExecuteGates -join ', ')"
    }

    $failClosed = @($anchor.WORKFLOW.fail_closed_on | ForEach-Object { [string]$_ })
    $requiredFailClosed = @(
        'anchor_missing',
        'anchor_invalid',
        'release_gate_not_PASS'
    )
    $missingFailClosed = @($requiredFailClosed | Where-Object { $failClosed -notcontains $_ })
    if ($missingFailClosed.Count -gt 0) {
        throw "goal anchor missing fail_closed_on entries: $($missingFailClosed -join ', ')"
    }

    if ([string]$anchor.StopPolicy.mode -ne 'MANUAL_ONLY') {
        throw "goal anchor StopPolicy.mode must be MANUAL_ONLY"
    }
    if (!$anchor.StopPolicy.do_not_self_declare_goal_complete) {
        throw "goal anchor StopPolicy.do_not_self_declare_goal_complete must be true"
    }

    return [ordered]@{
        ok = $true
        path = $path
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        schema = [string]$anchor.schema
        design_docs = $designDocs
        release_gate = [ordered]@{
            front_door = [string]$anchor.RELEASE_GATE.front_door
            command = [string]$anchor.RELEASE_GATE.command
            required_status = [string]$anchor.RELEASE_GATE.required_status
            receipt_pattern = [string]$anchor.RELEASE_GATE.receipt_pattern
        }
        execute_gate_ids = $executeGateIds
        stop_policy = [string]$anchor.StopPolicy.mode
    }
}

function Assert-CoreBackendConvergence {
    $backendPath = Join-Path $RepoRoot 'src\backend_contract.rs'
    $runtimePath = Join-Path $RepoRoot 'src\core_runtime.rs'
    $guiAppPath = Join-Path $RepoRoot 'src\gui_app.rs'
    if (!(Test-Path -LiteralPath $backendPath)) {
        throw 'backend contract module missing: src\backend_contract.rs'
    }
    if (!(Test-Path -LiteralPath $runtimePath)) {
        throw 'core runtime module missing: src\core_runtime.rs'
    }
    if (!(Test-Path -LiteralPath $guiAppPath)) {
        throw 'GUI app module missing: src\gui_app.rs'
    }

    $backendText = Get-Content -LiteralPath $backendPath -Raw
    $runtimeText = Get-Content -LiteralPath $runtimePath -Raw
    $guiAppText = Get-Content -LiteralPath $guiAppPath -Raw
    $backendForbidden = @(
        'crate::source_trust::import_publisher_key_pin_from_release_asset',
        'crate::update_candidate::check_latest_update_candidate',
        'crate::update_candidate::stage_latest_update_candidate',
        'crate::update_candidate::refused_update_candidate_check_report',
        'crate::update_candidate::refused_update_candidate_stage_report',
        'crate::update_candidate::UpdateCandidateCheckConfig',
        'crate::update_candidate::UpdateCandidateStageConfig',
        'crate::update_apply_plan::build_update_apply_plan',
        'crate::update_apply_plan::write_update_apply_plan_evidence_for_stage2',
        'parse_github_intent(',
        'crate::url_policy::official_github_artifact_hosts',
        'crate::github_intent::ParsedGithubIntent',
        'ParsedGithubIntent::',
        'crate::source_spec::SourceSpec',
        'crate::verification::verification_source_summary',
        'crate::trust_center::trust_center_snapshot',
        'crate::trust_center::TrustCenterSnapshot',
        'pub use crate::trust_center::publisher_key_source_label_for_policy',
        'pub use crate::trust_policy::file_disposition_summary',
        'pub use crate::trust_policy::open_location_button_label_for_facts',
        'pub use crate::source_trust::public_key_from_private_seed',
        'pub use crate::source_trust::sign_ed25519_detached',
        'pub use crate::source_trust::verify_ed25519_detached',
        'pub use crate::source_trust::{normalize_public_key_pin, trusted_key_fingerprint}',
        'pub use crate::bench::run_bench_download',
        'pub use crate::staged_release::run_staged_release_download_selftest',
        'pub use crate::update_apply_plan::run_update_apply_plan_contract_selftest',
        'pub use crate::update_candidate::run_update_candidate_contract_selftest',
        'pub use crate::update_candidate::run_update_candidate_latest_selftest',
        'pub use crate::update_candidate::run_update_candidate_stage_selftest',
        'pub use crate::history::default_history_path',
        'DownloadWithStrategyContractInput',
        'AppendDownloadHistoryInput',
        'VerificationHistoryContext',
        'std::time::Instant',
        'crate::url_policy::parse_and_validate_https_github_official_url',
        '.probe_download_best_effort(',
        '.choose_download_strategy(',
        '.verification_plan_from_download_context(',
        '.download_with_strategy_contract(',
        '.verify_downloaded_file(',
        '.plan_file_disposition_for_report(',
        '.append_download_history_best_effort(',
        '.apply_file_disposition_contract(',
        'use crate::download::build_client',
        'build_client(&self.proxy',
        'fn client(&self, timeout_secs',
        '.build_client('
    )
    $backendForbiddenRegex = @(
        '(?m)^\s*use\s+crate::source_trust::import_publisher_key_pin_from_release_asset',
        '(?m)^\s*use\s+crate::update_candidate::\{'
    )
    $present = @($backendForbidden | Where-Object {
        $backendText.IndexOf($_, [System.StringComparison]::Ordinal) -ge 0
    })
    $present += @($backendForbiddenRegex | Where-Object { $backendText -match $_ })
    if ($present.Count -gt 0) {
        throw "backend_contract owns orchestration that must live in CoreRuntime: $($present -join ', ')"
    }

    $runtimeRequired = @(
        'pub(crate) fn import_publisher_key_from_release_asset',
        'pub(crate) fn check_latest_update_candidate',
        'pub(crate) fn refused_update_candidate_check_report',
        'pub(crate) fn stage_latest_update_candidate',
        'pub(crate) fn refused_update_candidate_stage_report',
        'pub(crate) fn build_update_apply_plan_for_stage2',
        'pub(crate) fn record_update_apply_plan_evidence_for_stage2',
        'pub(crate) fn resolve_download_intent',
        'pub(crate) fn official_github_artifact_hosts',
        'pub(crate) fn default_history_path',
        'pub(crate) fn release_query_selector_label',
        'pub(crate) fn release_asset_picker_label',
        'pub(crate) fn trust_policy_from_settings',
        'pub(crate) fn verification_source_summary_for_selected_asset',
        'pub(crate) fn publisher_key_source_label_for_policy',
        'pub(crate) fn open_location_button_label_for_facts',
        'pub(crate) fn file_disposition_summary',
        'pub(crate) fn public_key_from_private_seed',
        'pub(crate) fn sign_ed25519_detached',
        'pub(crate) fn verify_ed25519_detached',
        'pub(crate) fn normalize_public_key_pin',
        'pub(crate) fn trusted_key_fingerprint',
        'pub(crate) fn run_bench_download',
        'pub(crate) fn run_staged_release_download_selftest',
        'pub(crate) fn run_update_candidate_contract_selftest',
        'pub(crate) fn run_update_candidate_latest_selftest',
        'pub(crate) fn run_update_candidate_stage_selftest',
        'pub(crate) fn run_update_apply_plan_contract_selftest',
        'pub(crate) fn resolve_release_context_for_download_best_effort',
        'pub(crate) fn trust_center_snapshot',
        'pub(crate) fn run_download_contract',
        'pub(crate) struct CoreClientSettings',
        'pub(crate) struct CoreDownloadSpec',
        'pub(crate) enum CoreDownloadIntent',
        'pub(crate) struct CoreTrustCenterSnapshot',
        'pub(crate) fn build_client',
        'pub(crate) fn resolve_release_assets_for_query',
        'pub(crate) fn import_publisher_key_from_release_asset_for_settings',
        'pub(crate) fn run_update_candidate_check',
        'pub(crate) fn run_update_candidate_stage'
    )
    $missing = @($runtimeRequired | Where-Object {
        $runtimeText.IndexOf($_, [System.StringComparison]::Ordinal) -lt 0
    })
    if ($missing.Count -gt 0) {
        throw "CoreRuntime missing backend convergence entrypoints: $($missing -join ', ')"
    }

    $guiForbidden = @(
        'backend_contract::ReleaseQueryKind::',
        'backend_contract::SourceTrustPolicyConfig'
    )
    $guiForbiddenRegex = @(
        '(?m)\basset_picker_label\('
    )
    $guiPresent = @($guiForbidden | Where-Object {
        $guiAppText.IndexOf($_, [System.StringComparison]::Ordinal) -ge 0
    })
    $guiPresent += @($guiForbiddenRegex | Where-Object { $guiAppText -match $_ })
    if ($guiPresent.Count -gt 0) {
        throw "GUI owns release DTO formatting that must route through backend_contract/CoreRuntime: $($guiPresent -join ', ')"
    }

    return [ordered]@{
        ok = $true
        contract = 'backend_contract remains a stable DTO/use-case door; self-update, publisher-key import, apply-plan, intent DTO boundary, official-artifact-host helper, history-path helper, release DTO display helpers, trust policy settings helper, verification-source summary, trust display helpers, source-trust crypto helpers, bench and selftest CLI behavior, release-context DTO boundary, release-context enrichment, Trust Center snapshot, client construction, client-bound backend use cases, and download/verify/history/disposition orchestration route through CoreRuntime'
        backend_contract = [ordered]@{
            path = $backendPath
            sha256 = (Get-FileHash -LiteralPath $backendPath -Algorithm SHA256).Hash
            forbidden_patterns_absent = $backendForbidden
            forbidden_regex_absent = $backendForbiddenRegex
        }
        core_runtime = [ordered]@{
            path = $runtimePath
            sha256 = (Get-FileHash -LiteralPath $runtimePath -Algorithm SHA256).Hash
            required_patterns = $runtimeRequired
        }
        gui_app = [ordered]@{
            path = $guiAppPath
            sha256 = (Get-FileHash -LiteralPath $guiAppPath -Algorithm SHA256).Hash
            forbidden_patterns_absent = $guiForbidden
            forbidden_regex_absent = $guiForbiddenRegex
        }
    }
}

$gitHead = @(Invoke-CapturedNative -Name 'provenance-git-head' -Exe 'git' -Arguments @('rev-parse', 'HEAD'))
$gitBranch = @(Invoke-CapturedNative -Name 'provenance-git-branch' -Exe 'git' -Arguments @('branch', '--show-current'))
$gitDescribe = @(Invoke-CapturedNative -Name 'provenance-git-describe' -Exe 'git' -Arguments @('describe', '--tags', '--always', '--dirty'))
$gitStatus = @(Invoke-CapturedNative -Name 'provenance-git-status' -Exe 'git' -Arguments @('status', '--short', '--branch'))
$rustcVersion = @(Invoke-CapturedNative -Name 'provenance-rustc-vv' -Exe 'rustc' -Arguments @('-vV'))
$cargoVersion = @(Invoke-CapturedNative -Name 'provenance-cargo-vv' -Exe 'cargo' -Arguments @('-vV'))

$Receipt.provenance = [ordered]@{
    git = [ordered]@{
        head = Get-FirstLineOrEmpty -Lines $gitHead
        branch = Get-FirstLineOrEmpty -Lines $gitBranch
        describe = Get-FirstLineOrEmpty -Lines $gitDescribe
        status_short = $gitStatus
    }
    toolchain = [ordered]@{
        rustc_vv = $rustcVersion
        cargo_vv = $cargoVersion
    }
    files = [ordered]@{
        repo_agents = Get-OptionalFileEvidence -RelativePath 'AGENTS.md'
        goal_anchor = Get-OptionalFileEvidence -RelativePath 'docs\GOAL-ANCHOR.json'
        readme = Get-OptionalFileEvidence -RelativePath 'README.md'
        roadmap = Get-OptionalFileEvidence -RelativePath 'docs\ROADMAP.md'
        architecture = Get-OptionalFileEvidence -RelativePath 'docs\ARCHITECTURE.md'
        cargo_lock = Get-OptionalFileEvidence -RelativePath 'Cargo.lock'
        rust_toolchain = Get-OptionalFileEvidence -RelativePath 'rust-toolchain.toml'
        ci_workflow = Get-OptionalFileEvidence -RelativePath '.github\workflows\ci.yml'
        release_workflow = Get-OptionalFileEvidence -RelativePath '.github\workflows\release.yml'
        release_verify_script = Get-OptionalFileEvidence -RelativePath 'tools\release-verify.ps1'
        trust_center_contract = Get-OptionalFileEvidence -RelativePath 'src\trust_center.rs'
    }
}

Invoke-LoggedNative -Name 'git-status' -Exe 'git' -Arguments @('status', '--short', '--branch')
$Receipt.checks.route_guardrails = [ordered]@{
    ok = $true
    goal_anchor = Assert-GoalAnchorContract
    design_doc_inventory = Assert-DesignDocInventory
    core_backend_convergence = Assert-CoreBackendConvergence
    agents = Assert-FileContains `
        -RelativePath 'AGENTS.md' `
        -RequiredPatterns @(
            'Windows-first Trusted GitHub Release Downloader',
            'Windows-first Artifact Trust Broker',
            'Windows Local Software Trust Root',
            'Do **not** let the UI make final trust verdicts',
            'tools\release-verify.ps1 + receipt.json',
            'docs\GOAL-ANCHOR.json',
            'Design/end-state route docs are anchored only'
        )
    readme = Assert-FileContains `
        -RelativePath 'README.md' `
        -RequiredPatterns @(
            'Windows-first Trusted GitHub Release Downloader',
            'Windows-first Artifact Trust Broker',
            'Windows Local Software Trust Root',
            'tools\release-verify.ps1 + receipt.json',
            'docs\GOAL-ANCHOR.json',
            'The durable design/end-state anchors are this README plus',
            'Run/audit evidence should stay in `target\delivery\<run_id>\` receipts'
        )
    roadmap = Assert-FileContains `
        -RelativePath 'docs\ROADMAP.md' `
        -RequiredPatterns @(
            'Signed source true end-to-end release',
            'Trust Center UI',
            'Auto-update MVP',
            'Core crate and backend contract',
            'Artifact Trust Broker',
            'Windows Local Software Trust Root'
        )
    architecture = Assert-FileContains `
        -RelativePath 'docs\ARCHITECTURE.md' `
        -RequiredPatterns @(
            'UI Shell',
            'Core / backend contract',
            'Verification engine',
            'Source trust engine',
            'Policy engine',
            'Evidence ledger',
            'Release verification front door'
        )
    architecture_convergence = [ordered]@{
        ok = $true
        contract = 'experiments must converge into one Windows UI + one core/backend trust chain + one release-verify receipt gate; no long-term dual tracks'
        agents = Assert-FileContains `
            -RelativePath 'AGENTS.md' `
            -RequiredPatterns @(
                'Windows UI',
                '`core/backend/API/evidence/policy`',
                'Do **not** keep long-term dual tracks',
                'Experiments must converge back into the single main chain or be removed'
            )
        roadmap = Assert-FileContains `
            -RelativePath 'docs\ROADMAP.md' `
            -RequiredPatterns @(
                'Not a second release pipeline beside `tools\release-verify.ps1`',
                '`tools\release-verify.ps1` as the single delivery front door',
                'UI stops making final trust decisions',
                'Do not expand scope here until the GitHub Release trust path and Artifact Trust Broker contracts are stable',
                'Avoid work that creates a second long-term path'
            )
        architecture = Assert-FileContains `
            -RelativePath 'docs\ARCHITECTURE.md' `
            -RequiredPatterns @(
                'one Windows UI',
                'trusted local acquisition backend with a thin UI shell',
                'UI must not',
                'invent final trust verdicts',
                'Do not daemonize before the core contract is clean',
                '`tools\release-verify.ps1` is the delivery judge'
            )
    }
}
$Receipt.checks.release_workflow_artifact_contract = Assert-ReleaseWorkflowArtifactContract
$Receipt.checks.release_signing_bootstrap_contract = Assert-ReleaseSigningBootstrapContract
$Receipt.checks.trust_center_backend_contract = Assert-TrustCenterBackendContract
$Receipt.checks.ui_shell_thinness = Assert-UiShellThinness
Invoke-LoggedNative -Name 'cargo-fmt-check' -Exe 'cargo' -Arguments @('fmt', '--check')
Invoke-LoggedNative -Name 'cargo-test-all-targets' -Exe 'cargo' -Arguments @('test', '--all-targets', '--locked')
$Receipt.checks.download_engine_contract = [ordered]@{
    ok = $true
    retry = 'transient request send failures are retried before a direct download fails'
    resumable = 'single-download resume and ignored-range restart paths are covered'
    segmented = 'segmented range writes and resume metadata cleanup are covered'
    covered_by = Assert-CommandLogContains `
        -CommandName 'cargo-test-all-targets' `
        -RequiredPatterns @(
            'download_single_retries_transient_request_send_failure',
            'download_single_creates_new_temp_file_with_write_access',
            'download_single_restarts_when_resume_range_is_ignored',
            'download_single_resumes_existing_part_file_with_range_request',
            'download_segmented_writes_all_ranges_and_removes_resume_meta'
        )
}
$Receipt.checks.github_url_intent_router_contract = [ordered]@{
    ok = $true
    contract = 'Router is pure (no network IO) and classifies GitHub official artifact URLs into intent DTOs'
    covered_by = Assert-CommandLogContains `
        -CommandName 'cargo-test-all-targets' `
        -RequiredPatterns @(
            'router_classifies_release_asset_download_url',
            'router_classifies_release_page_urls',
            'router_maps_blob_to_raw_download_spec',
            'router_accepts_raw_githubusercontent_urls',
            'router_rejects_non_artifact_github_urls'
        )
}
$Receipt.checks.trust_policy_contract = [ordered]@{
    ok = $true
    decision_transitions = [ordered]@{
        verified = 'VERIFIED -> TRUSTED'
        mismatch = 'MISMATCH -> BLOCK'
        unknown = 'UNKNOWN -> RISK'
    }
    policy_defaults = [ordered]@{
        unknown_keep_file = $true
        unknown_allow_open = $false
        mismatch_file_policy = 'QUARANTINE'
        source_trust_require_signed = $false
    }
    file_disposition = [ordered]@{
        verified = 'KEEP'
        mismatch = 'QUARANTINE_OR_DELETE_BY_POLICY'
        unknown = 'KEEP_OR_DELETE_BY_POLICY'
        verified_hash_untrusted_source = 'QUARANTINE_OR_DELETE_BY_POLICY'
    }
    source_trust = [ordered]@{
        signature_format = 'ed25519-detached-hex'
        good_signature = 'VERIFIED hash + TRUSTED_SIGNATURE source -> TRUSTED'
        bad_signature = 'VERIFIED hash + BAD_SIGNATURE source -> BLOCK'
        missing_signature_required = 'VERIFIED hash + MISSING_SIGNATURE required source -> BLOCK'
        missing_signature_optional = 'VERIFIED hash + UNSIGNED optional source -> allowed with source authenticity evidence'
        key_material = 'history/evidence store pinned key SHA256 fingerprint, not raw public key'
        verification_source_fetch = 'checksum/provenance and signature asset reads retry transient request/server failures before producing UNKNOWN or untrusted-source evidence'
    }
    history_evidence_schema = 'policy.schema_version=2 + policy.source_trust.schema_version=1 + source_trust.schema_version=1 + file_disposition.schema_version=1 REQUIRED_FOR_VERIFIED_MISMATCH_UNKNOWN_DOWNLOAD_REPORTS'
    gui_decision_points = 'SavedState persistence + Trust policy UI + Source trust pin/import/normalize/display/source label + selected-release publisher-key.ed25519.pub fetch/pin + Trust Center backend contract snapshot + downloaded asset/hash context + recorded policy-at-decision + pinned publisher key source + backend source-trust detail + Open Evidence exact path/access status + open_location_button_label_for_report'
    covered_by = Assert-CommandLogContains `
        -CommandName 'cargo-test-all-targets' `
        -RequiredPatterns @(
            'trust_policy_defaults_are_conservative_but_download_compatible',
            'file_disposition_plans_cover_verified_mismatch_and_unknown_policy',
            'source_trust_required_policy_quarantines_hash_verified_untrusted_source',
            'applies_quarantine_and_delete_file_dispositions',
            'gui_open_location_decision_respects_trust_policy',
            'gui_open_location_decision_blocks_untrusted_verified_source',
            'saved_state_persists_trust_policy_and_history_path',
            'publisher_key_import_accepts_release_public_key_asset',
            'publisher_key_import_result_updates_trust_policy_pin_and_status',
            'trust_center_snapshot_displays_backend_verdict_and_publisher_pin',
            'trust_center_snapshot_uses_recorded_policy_snapshot_for_last_download',
            'trust_center_snapshot_marks_publisher_key_source_unrecorded_when_missing',
            'trust_center_snapshot_surfaces_backend_source_trust_detail',
            'trust_center_snapshot_marks_openable_evidence_path',
            'trust_center_snapshot_includes_downloaded_asset_hash_context',
            'history_path_setting_uses_default_when_blank_and_custom_when_set',
            'completion_status_makes_mismatch_blocking_and_unknown_risky',
            'completion_status_blocks_untrusted_signed_source',
            'append_download_history_records_reviewable_verification_evidence',
            'append_download_history_records_block_and_risk_evidence_decisions',
            'history_evidence_records_source_trust_schema',
            'reports_verified_mismatch_and_unknown_states',
            'source_trust_verifies_good_and_bad_ed25519_signature',
            'source_trust_signs_detached_signature_that_verifier_accepts',
            'source_trust_derives_release_public_key_from_private_seed',
            'publisher_key_asset_import_fetches_normalizes_and_fingerprints_release_key',
            'publisher_key_asset_import_rejects_oversized_release_key_asset',
            'source_trust_missing_signature_blocks_only_when_required',
            'source_trust_no_key_blocks_required_policy',
            'source_trust_snapshot_records_key_fingerprint_not_raw_key',
            'parses_release_provenance_with_utf8_bom',
            'detects_checksum_and_provenance_assets_for_selected_release_asset',
            'verification_asset_fetch_retries_transient_server_failure',
            'verifies_downloaded_file_with_good_signed_checksum_source',
            'blocks_bad_signature_even_when_hash_matches',
            'required_source_trust_blocks_missing_signature'
        )
}
$Receipt.checks.update_candidate_unit_tests = [ordered]@{
    ok = $true
    contract = 'self-update candidate/staging: newer-only, gh_mirror_gui.exe only, hash VERIFIED, trusted signed source with pinned publisher key; Stage 2 stages locally but does not install/replace'
    covered_by = Assert-CommandLogContains `
        -CommandName 'cargo-test-all-targets' `
        -RequiredPatterns @(
            'update_candidate_accepts_newer_trusted_signed_release',
            'update_candidate_treats_same_version_as_no_update',
            'update_candidate_refuses_bad_signature',
            'update_candidate_refuses_missing_publisher_key',
            'update_candidate_refuses_unsigned_required_source',
            'latest_update_check_reports_no_update_without_downloading_candidate',
            'latest_update_check_accepts_newer_signed_candidate_with_pinned_key',
            'latest_update_check_refuses_newer_candidate_without_pinned_key_before_download',
            'latest_update_stage_stages_newer_signed_candidate_to_local_directory',
            'update_apply_plan_refuses_non_staged_report',
            'update_apply_plan_builds_reversible_steps_without_mutation'
        )
}
Invoke-LoggedNative -Name 'cargo-clippy-all-targets' -Exe 'cargo' -Arguments @('clippy', '--all-targets', '--locked', '--', '-D', 'warnings')
Invoke-LoggedNative -Name 'cargo-build-release' -Exe 'cargo' -Arguments @('build', '--release', '--locked')

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
$Receipt.checks.release_signing_readiness = [ordered]@{
    ok = $true
    workflow = Assert-FileContains `
        -RelativePath '.github\workflows\release.yml' `
        -RequiredPatterns @(
            'RELEASE_ED25519_PRIVATE_KEY_HEX repository secret is required; refusing unsigned release.',
            '--release-signing-doctor',
            'publisher-key.ed25519.pub',
            'SHA256SUMS.txt.sig',
            'release-provenance.json.sig'
        )
    readme = Assert-FileContains `
        -RelativePath 'README.md' `
        -RequiredPatterns @(
            '`RELEASE_ED25519_PRIVATE_KEY_HEX` is required for the next trusted release',
            '`publisher-key.ed25519.pub`',
            '`SHA256SUMS.txt.sig`',
            '`release-provenance.json.sig`'
        )
    roadmap = Assert-FileContains `
        -RelativePath 'docs\ROADMAP.md' `
        -RequiredPatterns @(
            'Release signing readiness doctor',
            '`RELEASE_ED25519_PRIVATE_KEY_HEX` is required before the next tag',
            '`publisher-key.ed25519.pub`'
        )
    architecture = Assert-FileContains `
        -RelativePath 'docs\ARCHITECTURE.md' `
        -RequiredPatterns @(
            'Release signing readiness',
            '`publisher-key.ed25519.pub`',
            '`RELEASE_ED25519_PRIVATE_KEY_HEX`'
        )
    local_doctor = Invoke-ReleaseSigningReadiness `
        -Exe $exe `
        -FixtureDir (Join-Path $EvidenceDir 'release-signing-fixture') `
        -JsonFile (Join-Path $EvidenceDir 'release-signing-readiness.json') `
        -PublicKeyOut (Join-Path $EvidenceDir 'publisher-key.ed25519.pub')
}
$Receipt.checks.signed_release_staging = Invoke-SignedReleaseStagingSelfTest `
    -Exe $exe `
    -StageDir (Join-Path $EvidenceDir 'signed-release-staging')
$Receipt.checks.update_candidate_contract = Invoke-UpdateCandidateContractSelfTest `
    -Exe $exe `
    -JsonFile (Join-Path $EvidenceDir 'update-candidate-contract.json')
$Receipt.checks.update_apply_plan_contract = Invoke-UpdateApplyPlanContractSelfTest `
    -Exe $exe `
    -JsonFile (Join-Path $EvidenceDir 'update-apply-plan-contract.json')
 
# Private repo compatibility:
# - PowerShell GitHub probes use `Get-GitHubAccessToken` directly.
# - Rust GitHub resolvers/selftests use `GITHUB_TOKEN` env var (see `src/releases.rs`).
# We only populate it when missing; the value is never written to receipts/logs/stdout.
if ([string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
    $token = Get-GitHubAccessToken
    if (![string]::IsNullOrWhiteSpace($token)) {
        $env:GITHUB_TOKEN = $token
    }
}

$originRelease = Invoke-GitHubLatestRelease -Repo 'wsolarq11/gh_mirror_gui'
$targetRelease = Invoke-GitHubLatestRelease -Repo 'carrot-hu23/dst-admin-go'
$Receipt.checks.origin_latest_release = $originRelease
$Receipt.checks.target_latest_release = $targetRelease
$Receipt.checks.origin_release_verification = Invoke-OriginReleaseVerificationSmoke `
    -Release $originRelease `
    -Exe $exe
$Receipt.checks.update_candidate_latest_selftest = Invoke-UpdateCandidateLatestSelfTest `
    -Exe $exe `
    -JsonFile (Join-Path $EvidenceDir 'update-candidate-latest-selftest.json')
$Receipt.checks.update_candidate_stage_selftest = Invoke-UpdateCandidateStageSelfTest `
    -Exe $exe `
    -JsonFile (Join-Path $EvidenceDir 'update-candidate-stage-selftest.json')

$doPostPublishStage2 = $PostPublishSelfUpdateStage2 -or !$SkipPostPublishSelfUpdateStage2

if ($doPostPublishStage2) {
    $expectedLatestTag = $null
    if ($originRelease.found) {
        $expectedLatestTag = [string]$originRelease.tag_name
    }
    $Receipt.checks.post_publish_self_update_stage2 = Invoke-PostPublishSelfUpdateStage2Check `
        -Repo 'wsolarq11/gh_mirror_gui' `
        -ExpectedLatestTag $expectedLatestTag `
        -Exe $exe
}
else {
    $Receipt.checks.post_publish_self_update_stage2 = [ordered]@{ skipped = $true }
}

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
    $benchmarkUrl = $targetAsset.browser_download_url
    $benchmarkFallback = $null
    $benchmarkRangeServer = $null
    try {
        try {
            $bench = Invoke-BenchVariant `
                -Name 'download-latest-asset' `
                -Url $benchmarkUrl `
                -OutFile $benchOut `
                -JsonFile $benchJson `
                -ExtraArgs @('--mode', 'auto')
        }
        catch {
            $remoteBenchmarkError = $_.Exception.Message
            $fallbackSource = Join-Path $EvidenceDir ("bench-fallback-source-$($targetAsset.name)")
            $ghResult = Save-ReleaseAssetWithGhFallback -Asset $targetAsset -OutFile $fallbackSource
            $benchmarkRangeServer = Start-LocalRangeFileServer `
                -FilePath $fallbackSource `
                -RouteName $targetAsset.name `
                -Name 'bench-local-range-server'
            $benchmarkUrl = $benchmarkRangeServer.url
            $bench = Invoke-BenchVariant `
                -Name 'download-latest-asset-local-range-fallback' `
                -Url $benchmarkUrl `
                -OutFile $benchOut `
                -JsonFile $benchJson `
                -ExtraArgs @('--mode', 'auto', '--allow-local-http')
            $benchmarkFallback = [ordered]@{
                degraded_from_url = $targetAsset.browser_download_url
                reason = $remoteBenchmarkError
                source_download = [ordered]@{
                    transport = $ghResult.transport
                    repo = $ghResult.repo
                    tag = $ghResult.tag
                    asset = $ghResult.asset
                    attempts = $ghResult.attempts
                    previous_errors = $ghResult.previous_errors
                    path = $fallbackSource
                    size = (Get-Item -LiteralPath $fallbackSource).Length
                    sha256 = (Get-FileHash -LiteralPath $fallbackSource -Algorithm SHA256).Hash
                }
                local_range_server = [ordered]@{
                    url = $benchmarkRangeServer.url
                    source = $benchmarkRangeServer.source
                    source_size = $benchmarkRangeServer.source_size
                    log = $benchmarkRangeServer.log_path
                }
            }
            $bench | Add-Member -NotePropertyName release_verify_degraded_benchmark -NotePropertyValue $benchmarkFallback -Force
        }

        $Receipt.checks.download_benchmark = $bench
        $Receipt.artifacts.benchmark_download = [ordered]@{
            path = $benchOut
            json = $benchJson
            size = (Get-Item -LiteralPath $benchOut).Length
            sha256 = (Get-FileHash -LiteralPath $benchOut -Algorithm SHA256).Hash
        }
        if ($null -ne $benchmarkFallback) {
            $Receipt.artifacts.benchmark_download.source = $benchmarkFallback.source_download
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
                    -Url $benchmarkUrl `
                    -OutFile $out `
                    -JsonFile $json `
                    -ExtraArgs (@($variant.args) + $(if ($null -ne $benchmarkFallback) { @('--allow-local-http') } else { @() }))
                $result | Add-Member -NotePropertyName variant -NotePropertyValue $variant.name -Force
                $matrix += $result
            }

            $curlOut = Join-Path $EvidenceDir ("matrix-curl-$($targetAsset.name)")
            $curlBench = Invoke-CurlBenchmark -Url $benchmarkUrl -OutFile $curlOut
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
    finally {
        Stop-LocalRangeFileServer -Server $benchmarkRangeServer
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

if ($SkipTargetGc) {
    $Receipt.checks.target_gc = [ordered]@{ skipped = $true }
}
else {
    $gcScript = Join-Path $RepoRoot 'tools\target-gc.ps1'
    if (!(Test-Path -LiteralPath $gcScript)) {
        $Receipt.checks.target_gc = [ordered]@{
            ok = $false
            error = "target-gc script not found: $gcScript"
        }
    }
    else {
        try {
            $gcJsonPath = Join-Path $EvidenceDir 'target-gc.json'
            $gcOutput = & $gcScript `
                -RepoRoot $RepoRoot `
                -KeepDeliveryRuns $KeepDeliveryRuns `
                -PruneIncremental:$PruneTargetIncremental
            $gcText = (@($gcOutput | ForEach-Object { $_.ToString() }) -join "`n")
            $gcText | Set-Content -LiteralPath $gcJsonPath -Encoding UTF8
            $Receipt.checks.target_gc = [ordered]@{
                ok = $true
                json = $gcJsonPath
                keep_delivery_runs = $KeepDeliveryRuns
                prune_incremental = [bool]$PruneTargetIncremental
            }
        }
        catch {
            $Receipt.checks.target_gc = [ordered]@{
                ok = $false
                error = $_.Exception.Message
            }
        }
    }
}

$Receipt.completed_at = (Get-Date).ToUniversalTime().ToString('o')
$Receipt.status = 'PASS'
$receiptPath = Join-Path $EvidenceDir 'receipt.json'
$Receipt | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

[ordered]@{
    status = 'PASS'
    receipt = $receiptPath
    provenance = $Receipt.provenance
    release_binary = $Receipt.artifacts.release_binary
    sha256sums = $Receipt.artifacts.sha256sums
} | ConvertTo-Json -Depth 10
