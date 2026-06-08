<#
.SYNOPSIS
    Intune Remediation Script - BitLocker compliance (safe actions only)
.DESCRIPTION
    Performs ONLY safe, non-destructive remediations for the BitLocker
    non-compliance scenarios detected by Detect-BitLockerCompliance.ps1:

    1. If protection is suspended (ProtectionStatus = Off but volume is
       encrypted), call Resume-BitLocker.
    2. If a RecoveryPassword protector exists but is not escrowed to
       Entra ID, call BackupToAAD-BitLockerKeyProtector for each
       RecoveryPassword KeyProtectorId.

    The following are NEVER performed automatically (require human review):
    - Starting BitLocker encryption on an unencrypted volume
    - Changing the encryption method (would require decrypt+re-encrypt)
    - Adding a TPM key protector (depends on TPM state / hardware)
    - Deleting / rotating existing key protectors

    For those cases the script exits 1 with a clear message so the device
    stays flagged as non-compliant for follow-up.

    Exit codes:
        0 = Remediation successful (or nothing safe to do but state will
            re-evaluate to compliant)
        1 = Remediation failed or non-compliance requires manual action
#>

#region Configuration
$AttemptResume      = $true
$AttemptAadEscrow   = $true
#endregion

#region Main
try {
    $systemDrive = $env:SystemDrive
    if (-not $systemDrive) { $systemDrive = 'C:' }

    $vol = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction Stop

    $actions  = @()
    $failures = @()

    # 1. Resume protection if suspended on an encrypted volume
    if ($AttemptResume `
        -and "$($vol.ProtectionStatus)" -ne 'On' `
        -and "$($vol.VolumeStatus)" -eq 'FullyEncrypted') {
        try {
            Resume-BitLocker -MountPoint $systemDrive -ErrorAction Stop | Out-Null
            $actions += "Resumed BitLocker protection on $systemDrive."
        } catch {
            $failures += "Resume-BitLocker failed on $systemDrive : $($_.Exception.Message)"
        }
        # Refresh state after resume attempt
        $vol = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction Stop
    }

    # 2. Backup RecoveryPassword key protectors to Entra ID
    if ($AttemptAadEscrow) {
        $rpProtectors = @($vol.KeyProtector |
            Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })

        if ($rpProtectors.Count -eq 0) {
            $failures += "No RecoveryPassword protector on $systemDrive. Cannot escrow to Entra ID. Manual action required (add a RecoveryPassword protector)."
        }
        else {
            foreach ($p in $rpProtectors) {
                try {
                    BackupToAAD-BitLockerKeyProtector -MountPoint $systemDrive -KeyProtectorId $p.KeyProtectorId -ErrorAction Stop | Out-Null
                    $actions += "Escrowed RecoveryPassword $($p.KeyProtectorId) to Entra ID."
                } catch {
                    $failures += "BackupToAAD-BitLockerKeyProtector failed for $($p.KeyProtectorId): $($_.Exception.Message)"
                }
            }
        }
    }

    # Flag conditions that require manual action
    if ("$($vol.VolumeStatus)" -ne 'FullyEncrypted' -and "$($vol.VolumeStatus)" -ne 'EncryptionInProgress') {
        $failures += "Drive $systemDrive is not encrypted (VolumeStatus=$($vol.VolumeStatus)). Encryption is not started automatically; review encryption policy assignment."
    }

    if ($actions.Count -gt 0) {
        Write-Output "Remediation actions performed:"
        $actions | ForEach-Object { Write-Output " - $_" }
    } else {
        Write-Output "No safe remediation actions were applicable."
    }

    if ($failures.Count -gt 0) {
        Write-Output "Issues requiring attention:"
        $failures | ForEach-Object { Write-Output " - $_" }
        exit 1
    }

    exit 0
}
catch {
    Write-Output "Remediation error: $($_.Exception.Message)"
    exit 1
}
#endregion
