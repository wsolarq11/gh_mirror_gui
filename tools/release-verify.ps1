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
                'staged_release_download_selftest_downloads_verifies_and_writes_evidence'
            )
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
                $digest = if ($_.PSObject.Properties.Name -contains 'digest') { $_.digest } else { $null }
                $contentType = if ($_.PSObject.Properties.Name -contains 'content_type') { $_.content_type } else { $null }
                [ordered]@{
                    name = $_.name
                    size = $_.size
                    content_type = $contentType
                    digest = $digest
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

function Save-ReleaseAsset {
    param(
        [object]$Asset,
        [string]$OutFile
    )

    Invoke-WebRequest `
        -Uri $Asset.browser_download_url `
        -Headers @{ 'User-Agent' = 'gh_mirror_gui-release-verify' } `
        -MaximumRedirection 10 `
        -OutFile $OutFile `
        -UseBasicParsing | Out-Null

    return [ordered]@{
        path = $OutFile
        size = (Get-Item -LiteralPath $OutFile).Length
        sha256 = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash
    }
}

function Invoke-OriginReleaseVerificationSmoke {
    param([object]$Release)

    if (!$Release.found) {
        throw "origin latest release lookup failed: $($Release.error)"
    }

    $binaryAsset = Get-ReleaseAssetByName -Release $Release -Name 'gh_mirror_gui.exe'
    $checksumAsset = Get-ReleaseAssetByName -Release $Release -Name 'SHA256SUMS.txt'
    $provenanceAsset = Get-ReleaseAssetByName -Release $Release -Name 'release-provenance.json'
    if ($null -eq $binaryAsset) {
        throw "origin release $($Release.tag_name) missing gh_mirror_gui.exe"
    }
    if ($null -eq $checksumAsset) {
        throw "origin release $($Release.tag_name) missing SHA256SUMS.txt"
    }
    if ($null -eq $provenanceAsset) {
        throw "origin release $($Release.tag_name) missing release-provenance.json"
    }

    $assetDir = Join-Path $EvidenceDir 'origin-release-verification'
    New-Item -ItemType Directory -Force -Path $assetDir | Out-Null
    $checksumPath = Join-Path $assetDir $checksumAsset.name
    $provenancePath = Join-Path $assetDir $provenanceAsset.name
    $checksumEvidence = Save-ReleaseAsset -Asset $checksumAsset -OutFile $checksumPath
    $provenanceEvidence = Save-ReleaseAsset -Asset $provenanceAsset -OutFile $provenancePath

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
        provenance_asset = [ordered]@{
            name = $provenanceAsset.name
            size = $provenanceAsset.size
            downloaded = $provenanceEvidence
        }
        expected_sha256 = $expectedHash
        provenance_release_tag = $provenance.release_tag
        provenance_package_version = $provenance.package_version
        provenance_github_sha = $provenance.github.sha
        github_asset_digest_sha256 = $binaryDigestHash
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
        readme = Get-OptionalFileEvidence -RelativePath 'README.md'
        roadmap = Get-OptionalFileEvidence -RelativePath 'docs\ROADMAP.md'
        architecture = Get-OptionalFileEvidence -RelativePath 'docs\ARCHITECTURE.md'
        cargo_lock = Get-OptionalFileEvidence -RelativePath 'Cargo.lock'
        rust_toolchain = Get-OptionalFileEvidence -RelativePath 'rust-toolchain.toml'
        ci_workflow = Get-OptionalFileEvidence -RelativePath '.github\workflows\ci.yml'
        release_workflow = Get-OptionalFileEvidence -RelativePath '.github\workflows\release.yml'
        release_verify_script = Get-OptionalFileEvidence -RelativePath 'tools\release-verify.ps1'
    }
}

Invoke-LoggedNative -Name 'git-status' -Exe 'git' -Arguments @('status', '--short', '--branch')
$Receipt.checks.route_guardrails = [ordered]@{
    ok = $true
    agents = Assert-FileContains `
        -RelativePath 'AGENTS.md' `
        -RequiredPatterns @(
            'Windows-first Trusted GitHub Release Downloader',
            'Windows-first Artifact Trust Broker',
            'Windows Local Software Trust Root',
            'Do **not** let the UI make final trust verdicts',
            'tools\release-verify.ps1 + receipt.json'
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
}
$Receipt.checks.release_workflow_artifact_contract = Assert-ReleaseWorkflowArtifactContract
Invoke-LoggedNative -Name 'cargo-fmt-check' -Exe 'cargo' -Arguments @('fmt', '--check')
Invoke-LoggedNative -Name 'cargo-test-all-targets' -Exe 'cargo' -Arguments @('test', '--all-targets', '--locked')
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
    }
    history_evidence_schema = 'policy.schema_version=2 + policy.source_trust.schema_version=1 + source_trust.schema_version=1 + file_disposition.schema_version=1 REQUIRED_FOR_VERIFIED_MISMATCH_UNKNOWN_DOWNLOAD_REPORTS'
    gui_decision_points = 'SavedState persistence + Trust policy UI + Source trust pin/import/normalize/display + Trust Center backend verdict snapshot + recorded policy-at-decision + Open Evidence exact path + open_location_button_label_for_report'
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
            'trust_center_snapshot_displays_backend_verdict_and_publisher_pin',
            'trust_center_snapshot_uses_recorded_policy_snapshot_for_last_download',
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
            'source_trust_missing_signature_blocks_only_when_required',
            'source_trust_no_key_blocks_required_policy',
            'source_trust_snapshot_records_key_fingerprint_not_raw_key',
            'parses_release_provenance_with_utf8_bom',
            'detects_checksum_and_provenance_assets_for_selected_release_asset',
            'verifies_downloaded_file_with_good_signed_checksum_source',
            'blocks_bad_signature_even_when_hash_matches',
            'required_source_trust_blocks_missing_signature'
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

$originRelease = Invoke-GitHubLatestRelease -Repo 'wsolarq11/gh_mirror_gui'
$targetRelease = Invoke-GitHubLatestRelease -Repo 'carrot-hu23/dst-admin-go'
$Receipt.checks.origin_latest_release = $originRelease
$Receipt.checks.target_latest_release = $targetRelease
$Receipt.checks.origin_release_verification = Invoke-OriginReleaseVerificationSmoke -Release $originRelease

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
        -ExtraArgs @('--mode', 'auto')
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
    provenance = $Receipt.provenance
    release_binary = $Receipt.artifacts.release_binary
    sha256sums = $Receipt.artifacts.sha256sums
} | ConvertTo-Json -Depth 10
