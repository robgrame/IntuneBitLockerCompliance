<#
.SYNOPSIS
    Intune Custom Compliance - Discovery script for BitLocker
.DESCRIPTION
    Returns a single JSON object (no other output) describing the
    BitLocker state of the system volume. The fields are flat (string,
    integer, boolean) so they can be matched by simple rules in the
    associated BitLockerComplianceRules.json file.

    REQUIREMENTS
    - The script MUST be signed with a code-signing certificate trusted
      by the target devices. Intune Custom Compliance refuses to run
      unsigned discovery scripts.
    - The script MUST emit one and only one JSON object to stdout.
      Any extra Write-Host / Write-Output will break parsing.

    Output schema (flat, all keys prefixed BL_ to identify them in Intune Settings reports):
        BL_MountPoint                   : string  ("C:")
        BL_ProtectionStatus             : string  ("On" | "Off" | ...)
        BL_VolumeStatus                 : string  ("FullyEncrypted" | ...)
        BL_EncryptionMethod             : string
        BL_EncryptionPercentage         : integer (0-100)
        BL_KeyProtectorTypes            : string  (comma-separated list)
        BL_HasTpmProtector              : boolean
        BL_HasRecoveryPasswordProtector : boolean
        BL_RecoveryKeyEscrowedInEntraId : boolean
        BL_EntraIdJoined                : boolean
        BL_TpmReady                     : boolean
        BL_NonComplianceReasons         : string  (' | ' separated, or empty)
#>

#region Helpers
function Test-IsEntraIdJoined {
    try {
        $out = & dsregcmd.exe /status 2>$null
        if (-not $out) { return $false }
        return [bool](($out | Select-String -SimpleMatch 'AzureAdJoined : YES') -ne $null)
    } catch { return $false }
}

function Test-RecoveryPasswordEscrowed {
    param([string[]] $RecoveryKeyIds)
    if (-not (Test-IsEntraIdJoined)) { return $false }
    if (-not $RecoveryKeyIds -or $RecoveryKeyIds.Count -eq 0) { return $false }
    try {
        # 2>$null + SilentlyContinue: suppress noise on devices where the log has no entries
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'
            Id      = 845
        } -ErrorAction SilentlyContinue 2>$null
        if (-not $events) { return $false }
    } catch { return $false }

    foreach ($kid in $RecoveryKeyIds) {
        $needle = $kid.Trim('{','}').ToLowerInvariant()
        $found  = $false
        foreach ($evt in $events) {
            if ($evt.Message -and $evt.Message.ToLowerInvariant().Contains($needle)) {
                $found = $true; break
            }
        }
        if (-not $found) { return $false }
    }
    return $true
}
#endregion

# Silence all non-terminating stream noise so stdout contains ONLY the final JSON line.
# Intune Custom Compliance requires the discovery script to emit exactly ONE JSON object.
$ErrorActionPreference   = 'SilentlyContinue'
$WarningPreference       = 'SilentlyContinue'
$VerbosePreference       = 'SilentlyContinue'
$InformationPreference   = 'SilentlyContinue'
$ProgressPreference      = 'SilentlyContinue'

try {
    $systemDrive = $env:SystemDrive
    if (-not $systemDrive) { $systemDrive = 'C:' }

    $vol = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction Stop

    $protectorTypes = @($vol.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
    $recoveryIds    = @($vol.KeyProtector |
        Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } |
        ForEach-Object { "$($_.KeyProtectorId)" })

    $tpmReady = $false
    try { $tpmReady = [bool](Get-Tpm -ErrorAction Stop).TpmReady } catch { }

    $entraJoined = Test-IsEntraIdJoined
    $escrowed    = Test-RecoveryPasswordEscrowed -RecoveryKeyIds $recoveryIds

    $reasons = New-Object System.Collections.Generic.List[string]
    if ("$($vol.ProtectionStatus)" -ne 'On') {
        $reasons.Add("Protection is $($vol.ProtectionStatus)")
    }
    if ("$($vol.VolumeStatus)" -ne 'FullyEncrypted') {
        $reasons.Add("VolumeStatus is $($vol.VolumeStatus) at $([int]$vol.EncryptionPercentage)%")
    }
    if ($protectorTypes -notcontains 'Tpm') {
        $reasons.Add("Missing TPM key protector")
    }
    if ($protectorTypes -notcontains 'RecoveryPassword') {
        $reasons.Add("Missing RecoveryPassword key protector")
    }
    if (-not $escrowed) {
        $reasons.Add("Recovery key not escrowed to Entra ID")
    }

    $result = [ordered]@{
        BL_MountPoint                   = "$systemDrive"
        BL_ProtectionStatus             = "$($vol.ProtectionStatus)"
        BL_VolumeStatus                 = "$($vol.VolumeStatus)"
        BL_EncryptionMethod             = "$($vol.EncryptionMethod)"
        BL_EncryptionPercentage         = [int64]$vol.EncryptionPercentage
        BL_KeyProtectorTypes            = ($protectorTypes -join ',')
        BL_HasTpmProtector              = [bool]($protectorTypes -contains 'Tpm')
        BL_HasRecoveryPasswordProtector = [bool]($protectorTypes -contains 'RecoveryPassword')
        BL_RecoveryKeyEscrowedInEntraId = [bool]$escrowed
        BL_EntraIdJoined                = [bool]$entraJoined
        BL_TpmReady                     = [bool]$tpmReady
        BL_NonComplianceReasons         = ($reasons -join ' | ')
    }

    # Emit exactly one line; Write-Host bypasses the success stream and
    # ConvertTo-Json -Compress guarantees a single line of JSON.
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}
catch {
    Write-Output (@{
        BL_MountPoint                   = "$env:SystemDrive"
        BL_ProtectionStatus             = "Error"
        BL_VolumeStatus                 = "Error"
        BL_EncryptionMethod             = "Unknown"
        BL_EncryptionPercentage         = [int64]0
        BL_KeyProtectorTypes            = ""
        BL_HasTpmProtector              = $false
        BL_HasRecoveryPasswordProtector = $false
        BL_RecoveryKeyEscrowedInEntraId = $false
        BL_EntraIdJoined                = $false
        BL_TpmReady                     = $false
        BL_NonComplianceReasons         = "Discovery error: $($_.Exception.Message)"
    } | ConvertTo-Json -Compress)
    exit 0
}
