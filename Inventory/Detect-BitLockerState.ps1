<#
.SYNOPSIS
    Intune Detection Script - BitLocker INVENTORY (state only, no compliance verdict)
.DESCRIPTION
    Reports the current BitLocker configuration for every fixed volume on
    the device: encryption algorithm, encryption percentage, volume status,
    protection status and key protectors (unlock parameters). When BitLocker
    is not configured for a volume the script still reports its presence
    and flags it as unencrypted.

    Designed to be deployed as an Intune Remediation with ONLY the detection
    script (Remediation script left empty). The script ALWAYS exits 0 so
    every device's state is captured in the "Detection output" column and
    available via Graph (deviceRunStates.detectionScriptOutput) for
    aggregation reports.

    Output:
    - Human-readable lines (one per volume)
    - A single machine-parsable line: BITLOCKER_STATE={...json...}

    Exit code:
        0 = always (this is an inventory script, not a compliance check)
#>

#region Helpers
function Get-VolumeBitLockerSnapshot {
    param([string] $MountPoint)
    try {
        $v = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
        $protectors = @($v.KeyProtector | ForEach-Object {
            [ordered]@{
                Type             = "$($_.KeyProtectorType)"
                Id               = "$($_.KeyProtectorId)"
                AutoUnlockEnabled = [bool]$_.AutoUnlockProtector
            }
        })
        return [ordered]@{
            MountPoint           = "$MountPoint"
            Present              = $true
            ProtectionStatus     = "$($v.ProtectionStatus)"
            VolumeStatus         = "$($v.VolumeStatus)"
            EncryptionMethod     = "$($v.EncryptionMethod)"
            EncryptionPercentage = [int]$v.EncryptionPercentage
            WipePercentage       = [int]$v.WipePercentage
            LockStatus           = "$($v.LockStatus)"
            AutoUnlockEnabled    = [bool]$v.AutoUnlockEnabled
            CapacityGB           = [math]::Round(($v.CapacityGB), 2)
            KeyProtectors        = $protectors
            KeyProtectorTypes    = ($protectors | ForEach-Object { $_.Type })
            HasTpmProtector      = [bool](($protectors | Where-Object Type -eq 'Tpm').Count -gt 0)
            HasRecoveryPassword  = [bool](($protectors | Where-Object Type -eq 'RecoveryPassword').Count -gt 0)
            HasPinProtector      = [bool](($protectors | Where-Object { $_.Type -in 'TpmPin','TpmPinStartupKey' }).Count -gt 0)
            HasStartupKey        = [bool](($protectors | Where-Object { $_.Type -in 'StartupKey','TpmStartupKey','TpmPinStartupKey' }).Count -gt 0)
            HasPasswordProtector = [bool](($protectors | Where-Object Type -eq 'Password').Count -gt 0)
        }
    } catch {
        return [ordered]@{
            MountPoint = "$MountPoint"
            Present    = $false
            Error      = "$($_.Exception.Message)"
        }
    }
}

function Get-FixedDriveMountPoints {
    try {
        Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
            ForEach-Object { $_.DeviceID }
    } catch {
        @($env:SystemDrive)
    }
}

function Get-TpmSummary {
    try {
        $t = Get-Tpm -ErrorAction Stop
        [ordered]@{
            Present                = [bool]$t.TpmPresent
            Ready                  = [bool]$t.TpmReady
            Enabled                = [bool]$t.TpmEnabled
            Activated              = [bool]$t.TpmActivated
            Owned                  = [bool]$t.TpmOwned
            ManufacturerIdTxt      = "$($t.ManufacturerIdTxt)"
            ManufacturerVersion    = "$($t.ManufacturerVersion)"
        }
    } catch {
        [ordered]@{ Present=$false; Ready=$false; Enabled=$false; Error="$($_.Exception.Message)" }
    }
}
#endregion

#region Main
try {
    $mounts  = Get-FixedDriveMountPoints
    $volumes = foreach ($m in $mounts) { Get-VolumeBitLockerSnapshot -MountPoint $m }

    $systemDrive = $env:SystemDrive
    if (-not $systemDrive) { $systemDrive = 'C:' }

    $sys = $volumes | Where-Object { $_.MountPoint -eq $systemDrive } | Select-Object -First 1

    $state = [ordered]@{
        DeviceName         = $env:COMPUTERNAME
        SystemDrive        = $systemDrive
        SystemDriveEncrypted = [bool]($sys -and $sys.Present -and $sys.ProtectionStatus -eq 'On' -and $sys.VolumeStatus -eq 'FullyEncrypted')
        SystemDriveMethod  = if ($sys) { $sys.EncryptionMethod } else { 'Unknown' }
        SystemDriveProtectors = if ($sys -and $sys.KeyProtectorTypes) { ($sys.KeyProtectorTypes -join ',') } else { '' }
        Tpm                = Get-TpmSummary
        Volumes            = $volumes
        CollectedAt        = (Get-Date).ToString('o')
    }

    Write-Output "BitLocker inventory for $($env:COMPUTERNAME)"
    foreach ($v in $volumes) {
        if ($v.Present) {
            Write-Output (" - {0} : {1} / {2} / {3} ({4}%) protectors={5}" -f `
                $v.MountPoint, $v.ProtectionStatus, $v.VolumeStatus,
                $v.EncryptionMethod, $v.EncryptionPercentage,
                (($v.KeyProtectorTypes) -join ','))
        } else {
            Write-Output (" - {0} : NOT a BitLocker volume / not configured ({1})" -f $v.MountPoint, $v.Error)
        }
    }
    Write-Output "BITLOCKER_STATE=$($state | ConvertTo-Json -Compress -Depth 6)"
    exit 0
}
catch {
    Write-Output "Inventory error: $($_.Exception.Message)"
    Write-Output "BITLOCKER_STATE=$(@{Error=$_.Exception.Message;CollectedAt=(Get-Date).ToString('o')} | ConvertTo-Json -Compress)"
    exit 0
}
#endregion
