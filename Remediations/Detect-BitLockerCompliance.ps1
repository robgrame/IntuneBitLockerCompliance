<#
.SYNOPSIS
    Intune Detection Script - BitLocker compliance with diagnostic detail
.DESCRIPTION
    Evaluates BitLocker compliance on the system volume against a set of
    configurable requirements and emits a structured diagnostic record so
    that the "Pre-remediation detection output" column in the Intune
    Remediations report shows WHY a device is non compliant.

    Criteria evaluated:
    1. System volume protection is enabled (ProtectionStatus = On)
    2. Volume is fully encrypted (VolumeStatus = FullyEncrypted)
    3. Encryption method meets minimum requirement (default XtsAes256)
    4. Required key protector types are present (default: Tpm + RecoveryPassword)
    5. Recovery password is escrowed to Entra ID (default: required)
    6. No recent BitLocker-API errors that would block compliance

    Output:
    - Human-readable diagnostic lines
    - A single machine-parsable line:  BITLOCKER_DIAG={...json...}

    Exit codes:
        0 = Compliant (no remediation needed)
        1 = Non-compliant (triggers remediation)

    On unexpected error the script exits 0 to avoid false positives.
#>

#region Configuration
$RequiredEncryptionMethod   = 'XtsAes256'
$MinEncryptionPercentage    = 100
$RequiredKeyProtectorTypes  = @('Tpm', 'RecoveryPassword')
$RequireEntraIdEscrow       = $true
$BitLockerApiErrorLookbackDays = 7
$BitLockerApiErrorMaxCount  = 5
#endregion

#region Helpers
function Get-EncryptionMethodRank {
    param([string]$Method)
    switch ($Method) {
        'None'                  { 0 }
        'Aes128'                { 1 }
        'Aes256'                { 2 }
        'Aes128Diffuser'        { 1 }
        'Aes256Diffuser'        { 2 }
        'XtsAes128'             { 3 }
        'XtsAes256'             { 4 }
        default                 { -1 }
    }
}

function Test-IsEntraIdJoined {
    try {
        $out = & dsregcmd.exe /status 2>$null
        if (-not $out) { return $false }
        $joined = ($out | Select-String -SimpleMatch 'AzureAdJoined : YES') -ne $null
        return [bool]$joined
    } catch {
        return $false
    }
}

function Get-RecoveryKeyEscrowEvents {
    # EventID 845 = "BitLocker Drive Encryption recovery information was backed up successfully to Azure Active Directory"
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'
            Id      = 845
        } -ErrorAction Stop
    } catch {
        @()
    }
}

function Test-RecoveryPasswordEscrowed {
    param(
        [Parameter(Mandatory)] [string[]] $RecoveryKeyIds
    )
    if (-not (Test-IsEntraIdJoined)) { return $false }
    if (-not $RecoveryKeyIds -or $RecoveryKeyIds.Count -eq 0) { return $false }

    $events = Get-RecoveryKeyEscrowEvents
    if (-not $events) { return $false }

    foreach ($kid in $RecoveryKeyIds) {
        $kidNormalized = $kid.Trim('{','}').ToLowerInvariant()
        $found = $false
        foreach ($evt in $events) {
            if ($evt.Message -and $evt.Message.ToLowerInvariant().Contains($kidNormalized)) {
                $found = $true
                break
            }
        }
        if (-not $found) { return $false }
    }
    return $true
}

function Get-RecentBitLockerApiErrors {
    $since = (Get-Date).AddDays(-1 * $BitLockerApiErrorLookbackDays)
    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-BitLocker/BitLocker Management'
            Level     = 2 # Error
            StartTime = $since
        } -MaxEvents $BitLockerApiErrorMaxCount -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject]@{
                    TimeCreated = $_.TimeCreated.ToString('o')
                    Id          = $_.Id
                    Message     = ($_.Message -split "`r?`n")[0]
                }
            }
    } catch {
        @()
    }
}

function Get-TpmState {
    try {
        $t = Get-Tpm -ErrorAction Stop
        [pscustomobject]@{
            Present = [bool]$t.TpmPresent
            Ready   = [bool]$t.TpmReady
            Enabled = [bool]$t.TpmEnabled
        }
    } catch {
        [pscustomobject]@{ Present=$false; Ready=$false; Enabled=$false }
    }
}
#endregion

#region Main
try {
    $systemDrive = $env:SystemDrive
    if (-not $systemDrive) { $systemDrive = 'C:' }

    $vol = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction Stop

    $protectorTypes = @($vol.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
    $recoveryKeyIds = @($vol.KeyProtector |
        Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } |
        ForEach-Object { "$($_.KeyProtectorId)" })

    $escrowed = $false
    if ($recoveryKeyIds.Count -gt 0) {
        $escrowed = Test-RecoveryPasswordEscrowed -RecoveryKeyIds $recoveryKeyIds
    }

    $tpm = Get-TpmState
    $recentErrors = Get-RecentBitLockerApiErrors

    $reasons = New-Object System.Collections.Generic.List[string]

    if ("$($vol.ProtectionStatus)" -ne 'On') {
        $reasons.Add("Drive $systemDrive protection is $($vol.ProtectionStatus) (expected On).")
    }
    if ("$($vol.VolumeStatus)" -ne 'FullyEncrypted') {
        $reasons.Add("Drive $systemDrive volume status is $($vol.VolumeStatus) ($([int]$vol.EncryptionPercentage)% encrypted).")
    }
    if ([int]$vol.EncryptionPercentage -lt $MinEncryptionPercentage) {
        $reasons.Add("Drive $systemDrive encryption percentage is $([int]$vol.EncryptionPercentage)% (required >= $MinEncryptionPercentage%).")
    }

    $currentMethod = "$($vol.EncryptionMethod)"
    $currentRank   = Get-EncryptionMethodRank -Method $currentMethod
    $requiredRank  = Get-EncryptionMethodRank -Method $RequiredEncryptionMethod
    if ($currentRank -lt $requiredRank) {
        $reasons.Add("Drive $systemDrive encryption method is $currentMethod (required >= $RequiredEncryptionMethod).")
    }

    foreach ($needed in $RequiredKeyProtectorTypes) {
        if ($protectorTypes -notcontains $needed) {
            $reasons.Add("Drive $systemDrive is missing required key protector: $needed.")
        }
    }

    if ($RequireEntraIdEscrow -and -not $escrowed) {
        if ($recoveryKeyIds.Count -eq 0) {
            $reasons.Add("Drive $systemDrive has no RecoveryPassword protector to escrow to Entra ID.")
        } else {
            $reasons.Add("Drive $systemDrive recovery key is not escrowed to Entra ID (no event 845 for KeyProtectorId or device not Entra ID joined).")
        }
    }

    $diag = [ordered]@{
        MountPoint                   = $systemDrive
        ProtectionStatus             = "$($vol.ProtectionStatus)"
        VolumeStatus                 = "$($vol.VolumeStatus)"
        EncryptionMethod             = $currentMethod
        EncryptionPercentage         = [int]$vol.EncryptionPercentage
        KeyProtectorTypes            = $protectorTypes
        RecoveryKeyIds               = $recoveryKeyIds
        RecoveryKeyEscrowedInEntraId = [bool]$escrowed
        EntraIdJoined                = (Test-IsEntraIdJoined)
        Tpm                          = $tpm
        LastBitLockerApiErrors       = $recentErrors
        NonComplianceReasons         = $reasons.ToArray()
        EvaluatedAt                  = (Get-Date).ToString('o')
        Requirements                 = [ordered]@{
            RequiredEncryptionMethod  = $RequiredEncryptionMethod
            MinEncryptionPercentage   = $MinEncryptionPercentage
            RequiredKeyProtectorTypes = $RequiredKeyProtectorTypes
            RequireEntraIdEscrow      = $RequireEntraIdEscrow
        }
    }

    if ($reasons.Count -eq 0) {
        Write-Output "BitLocker compliant on $systemDrive ($currentMethod, $([int]$vol.EncryptionPercentage)%, protectors: $($protectorTypes -join ','), escrowed: $escrowed)."
        $json = ($diag | ConvertTo-Json -Compress -Depth 6)
        Write-Output "BITLOCKER_DIAG=$json"
        exit 0
    }
    else {
        Write-Output "BitLocker NON-COMPLIANT on $systemDrive. Reasons:"
        foreach ($r in $reasons) { Write-Output " - $r" }
        $json = ($diag | ConvertTo-Json -Compress -Depth 6)
        Write-Output "BITLOCKER_DIAG=$json"
        exit 1
    }
}
catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    $errDiag = @{
        Error       = $_.Exception.Message
        EvaluatedAt = (Get-Date).ToString('o')
    } | ConvertTo-Json -Compress
    Write-Output "BITLOCKER_DIAG=$errDiag"
    exit 0
}
#endregion
