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

    Output schema (flat):
        MountPoint                   : string  ("C:")
        ProtectionStatus             : string  ("On" | "Off" | ...)
        VolumeStatus                 : string  ("FullyEncrypted" | ...)
        EncryptionMethod             : string
        EncryptionPercentage         : integer (0-100)
        KeyProtectorTypes            : string  (comma-separated list)
        HasTpmProtector              : boolean
        HasRecoveryPasswordProtector : boolean
        RecoveryKeyEscrowedInEntraId : boolean
        EntraIdJoined                : boolean
        TpmReady                     : boolean
        NonComplianceReasons         : string  (' | ' separated, or empty)
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
        } -ErrorAction Stop
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
        MountPoint                   = "$systemDrive"
        ProtectionStatus             = "$($vol.ProtectionStatus)"
        VolumeStatus                 = "$($vol.VolumeStatus)"
        EncryptionMethod             = "$($vol.EncryptionMethod)"
        EncryptionPercentage         = [int]$vol.EncryptionPercentage
        KeyProtectorTypes            = ($protectorTypes -join ',')
        HasTpmProtector              = [bool]($protectorTypes -contains 'Tpm')
        HasRecoveryPasswordProtector = [bool]($protectorTypes -contains 'RecoveryPassword')
        RecoveryKeyEscrowedInEntraId = [bool]$escrowed
        EntraIdJoined                = [bool]$entraJoined
        TpmReady                     = [bool]$tpmReady
        NonComplianceReasons         = ($reasons -join ' | ')
    }

    return ($result | ConvertTo-Json -Compress)
}
catch {
    # On error emit a JSON with the error so the rule engine can flag it
    return (@{
        MountPoint                   = "$env:SystemDrive"
        ProtectionStatus             = "Error"
        VolumeStatus                 = "Error"
        EncryptionMethod             = "Unknown"
        EncryptionPercentage         = 0
        KeyProtectorTypes            = ""
        HasTpmProtector              = $false
        HasRecoveryPasswordProtector = $false
        RecoveryKeyEscrowedInEntraId = $false
        EntraIdJoined                = $false
        TpmReady                     = $false
        NonComplianceReasons         = "Discovery error: $($_.Exception.Message)"
    } | ConvertTo-Json -Compress)
}
