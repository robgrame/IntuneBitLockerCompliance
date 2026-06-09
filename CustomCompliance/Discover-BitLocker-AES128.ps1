<#
.SYNOPSIS
    Intune Custom Compliance - Discovery script for BitLocker (AES-128 variant)

.DESCRIPTION
    Variante della policy BitLocker che accetta come algoritmo di cifratura
    `Aes128` (AES-CBC 128 legacy) OPPURE `XtsAes256` (XTS-AES 256 moderno).
    Tutti gli altri 5 controlli (ProtectionOn, FullyEncrypted, EncryptionComplete,
    TPM protector, RecoveryPassword protector) sono identici alla policy principale.

    Output: una sola riga JSON valido (vedi schema in fondo).
    Lo script DEVE essere firmato (signed) per essere caricato in Custom
    Compliance (oppure disabilitare 'Enforce signature check' sullo script
    in *Devices > Compliance > Scripts*).

    Da abbinare a: BitLockerComplianceRules-AES128.json

    Output schema (flat). Setting evaluated booleans + raw diagnostic fields:

        Evaluated booleans (referenced by BitLockerComplianceRules-AES128.json):
            BL_IsProtectionOn                       : Bool
            BL_IsVolumeFullyEncrypted               : Bool
            BL_IsEncryptionComplete                 : Bool (>=100%)
            BL_IsEncryptionMethodAes128OrXtsAes256  : Bool (Aes128 OR XtsAes256)
            BL_HasTpmProtector                      : Bool
            BL_HasRecoveryPasswordProtector         : Bool

        Raw diagnostic fields (NOT evaluated):
            BL_MountPoint, BL_ProtectionStatus, BL_VolumeStatus,
            BL_EncryptionMethod, BL_EncryptionPercentage,
            BL_KeyProtectorTypes, BL_IsRecoveryKeyEscrowedInEntraId (unreliable),
            BL_EntraIdJoined, BL_TpmReady, BL_NonComplianceReasons
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

# Silence non-stdout streams; Custom Compliance discovery must emit ONE JSON line only
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

    $methodStr = "$($vol.EncryptionMethod)"
    $isAccepted = ($methodStr -eq 'Aes128' -or $methodStr -eq 'XtsAes256')

    $reasons = New-Object System.Collections.Generic.List[string]
    if ("$($vol.ProtectionStatus)" -ne 'On') {
        $reasons.Add("Protection is $($vol.ProtectionStatus)")
    }
    if ("$($vol.VolumeStatus)" -ne 'FullyEncrypted') {
        $reasons.Add("VolumeStatus is $($vol.VolumeStatus) at $([int]$vol.EncryptionPercentage)%")
    }
    if (-not $isAccepted) {
        $reasons.Add("EncryptionMethod is $methodStr (expected Aes128 or XtsAes256)")
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
        BL_IsEncryptionMethodAes128OrXtsAes256 = [bool]$isAccepted
        BL_HasTpmProtector                 = [bool]($protectorTypes -contains 'Tpm')
        BL_HasRecoveryPasswordProtector    = [bool]($protectorTypes -contains 'RecoveryPassword')

        # NOTE: BL_IsRecoveryKeyEscrowedInEntraId is emitted for diagnostic
        # purposes only and NOT referenced by BitLockerComplianceRules-AES128.json
        # (EventID-845 lookup is unreliable). Use Entra ID portal as source of truth.
        BL_IsRecoveryKeyEscrowedInEntraId  = [bool]$escrowed

        # ---- Raw diagnostic fields (NOT evaluated by rules; carried for debugging) ----
        BL_MountPoint                      = "$systemDrive"
        BL_ProtectionStatus                = "$($vol.ProtectionStatus)"
        BL_VolumeStatus                    = "$($vol.VolumeStatus)"
        BL_EncryptionMethod                = "$methodStr"
        BL_EncryptionPercentage            = [int64]$vol.EncryptionPercentage
        BL_KeyProtectorTypes               = ($protectorTypes -join ',')
        BL_EntraIdJoined                   = [bool]$entraJoined
        BL_TpmReady                        = [bool]$tpmReady
        BL_NonComplianceReasons            = ($reasons -join ' | ')
    }

    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}
catch {
    Write-Output (@{
        BL_IsProtectionOn                  = $false
        BL_IsVolumeFullyEncrypted          = $false
        BL_IsEncryptionComplete            = $false
        BL_IsEncryptionMethodAes128OrXtsAes256 = $false
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
