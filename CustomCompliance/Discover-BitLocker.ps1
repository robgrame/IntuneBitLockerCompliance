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

    Output schema (flat). Keys prefixed BL_*; *evaluated* settings encode the
    expected value in the name (Is*/Has*) so the Intune per-setting report
    is self-documenting (e.g. "BL_IsEncryptionMethodXtsAes256 = Compliant"):

        Evaluated booleans (referenced by BitLockerComplianceRules.json):
            BL_IsProtectionOn                  : Bool (true = ProtectionStatus == 'On')
            BL_IsVolumeFullyEncrypted          : Bool (true = VolumeStatus  == 'FullyEncrypted')
            BL_IsEncryptionComplete            : Bool (true = EncryptionPercentage >= 100)
            BL_IsEncryptionMethodXtsAes256     : Bool (true = EncryptionMethod == 'XtsAes256')
            BL_HasTpmProtector                 : Bool
            BL_HasRecoveryPasswordProtector    : Bool
            BL_IsRecoveryKeyEscrowedInEntraId  : Bool

        Raw diagnostic fields (NOT evaluated; emitted for debugging):
            BL_MountPoint                      : String  ("C:")
            BL_ProtectionStatus                : String  ("On" | "Off" | ...)
            BL_VolumeStatus                    : String
            BL_EncryptionMethod                : String
            BL_EncryptionPercentage            : Int64
            BL_KeyProtectorTypes               : String  (comma-separated)
            BL_EntraIdJoined                   : Bool
            BL_TpmReady                        : Bool
            BL_NonComplianceReasons            : String  (' | ' separated)
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
        # ---- Self-documenting boolean settings evaluated by Custom Compliance rules ----
        BL_IsProtectionOn                  = [bool]("$($vol.ProtectionStatus)" -eq 'On')
        BL_IsVolumeFullyEncrypted          = [bool]("$($vol.VolumeStatus)" -eq 'FullyEncrypted')
        BL_IsEncryptionComplete            = [bool]([int]$vol.EncryptionPercentage -ge 100)
        BL_IsEncryptionMethodXtsAes256     = [bool]("$($vol.EncryptionMethod)" -eq 'XtsAes256')
        BL_HasTpmProtector                 = [bool]($protectorTypes -contains 'Tpm')
        BL_HasRecoveryPasswordProtector    = [bool]($protectorTypes -contains 'RecoveryPassword')
        BL_IsRecoveryKeyEscrowedInEntraId  = [bool]$escrowed

        # ---- Raw diagnostic fields (NOT evaluated by rules; carried for debugging) ----
        BL_MountPoint                      = "$systemDrive"
        BL_ProtectionStatus                = "$($vol.ProtectionStatus)"
        BL_VolumeStatus                    = "$($vol.VolumeStatus)"
        BL_EncryptionMethod                = "$($vol.EncryptionMethod)"
        BL_EncryptionPercentage            = [int64]$vol.EncryptionPercentage
        BL_KeyProtectorTypes               = ($protectorTypes -join ',')
        BL_EntraIdJoined                   = [bool]$entraJoined
        BL_TpmReady                        = [bool]$tpmReady
        BL_NonComplianceReasons            = ($reasons -join ' | ')
    }

    # Emit exactly one line; Write-Host bypasses the success stream and
    # ConvertTo-Json -Compress guarantees a single line of JSON.
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}
catch {
    Write-Output (@{
        BL_IsProtectionOn                  = $false
        BL_IsVolumeFullyEncrypted          = $false
        BL_IsEncryptionComplete            = $false
        BL_IsEncryptionMethodXtsAes256     = $false
        BL_HasTpmProtector                 = $false
        BL_HasRecoveryPasswordProtector    = $false
        BL_IsRecoveryKeyEscrowedInEntraId  = $false
        BL_MountPoint                      = "$env:SystemDrive"
        BL_ProtectionStatus                = "Error"
        BL_VolumeStatus                    = "Error"
        BL_EncryptionMethod                = "Unknown"
        BL_EncryptionPercentage            = [int64]0
        BL_KeyProtectorTypes               = ""
        BL_EntraIdJoined                   = $false
        BL_TpmReady                        = $false
        BL_NonComplianceReasons            = "Discovery error: $($_.Exception.Message)"
    } | ConvertTo-Json -Compress)
    exit 0
}
