<#
.SYNOPSIS
    Generates a detailed BitLocker INVENTORY report from Intune Remediations.
.DESCRIPTION
    Queries Microsoft Graph for the device run states of the
    Detect-BitLockerState.ps1 inventory script, extracts the
    BITLOCKER_STATE={json} payload and produces CSV (+ optional HTML)
    with one row per device and per fixed volume.

    Works for both:
    - inventory scripts (exit 0)  -> reads detectionScriptOutput
    - compliance scripts (exit 1) -> reads preRemediationDetectionScriptOutput

    Permissions: DeviceManagementManagedDevices.Read.All,
                 DeviceManagementConfiguration.Read.All
.PARAMETER ScriptId
    The Id of the Intune Remediation (deviceHealthScript).
.EXAMPLE
    Connect-MgGraph -Scopes DeviceManagementManagedDevices.Read.All,DeviceManagementConfiguration.Read.All
    .\Get-BitLockerInventoryReport.ps1 -ScriptId <GUID> -OutputCsv .\inv.csv -OutputHtml .\inv.html
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ScriptId,
    [Parameter(Mandatory)] [string] $OutputCsv,
    [string] $OutputHtml
)

if (-not (Get-MgContext)) {
    throw "Run Connect-MgGraph first with DeviceManagementManagedDevices.Read.All and DeviceManagementConfiguration.Read.All scopes."
}

$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$ScriptId/deviceRunStates?`$expand=managedDevice&`$top=500"

$rows = New-Object System.Collections.Generic.List[object]
do {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    foreach ($run in $resp.value) {
        $output  = "$($run.detectionScriptOutput)$([Environment]::NewLine)$($run.preRemediationDetectionScriptOutput)"
        $state   = $null
        $match   = [regex]::Match($output, '(?:BITLOCKER_STATE|BITLOCKER_DIAG)=(\{.*\})')
        if ($match.Success) {
            try { $state = $match.Groups[1].Value | ConvertFrom-Json } catch { }
        }

        # Emit one row per fixed volume (or one fallback row if no volume info)
        $volumes = @()
        if ($state -and $state.Volumes) { $volumes = @($state.Volumes) }

        if ($volumes.Count -eq 0) {
            $rows.Add([pscustomobject]@{
                DeviceName        = $run.managedDevice.deviceName
                UserPrincipalName = $run.managedDevice.userPrincipalName
                OSVersion         = $run.managedDevice.osVersion
                LastUpdate        = $run.lastStateUpdateDateTime
                MountPoint        = ''
                Encrypted         = $state.SystemDriveEncrypted
                EncryptionMethod  = $state.SystemDriveMethod
                Protectors        = $state.SystemDriveProtectors
                ProtectionStatus  = ''
                VolumeStatus      = ''
                EncryptionPercent = ''
                TpmReady          = $state.Tpm.Ready
                RawOutput         = $output
            })
            continue
        }

        foreach ($v in $volumes) {
            $rows.Add([pscustomobject]@{
                DeviceName        = $run.managedDevice.deviceName
                UserPrincipalName = $run.managedDevice.userPrincipalName
                OSVersion         = $run.managedDevice.osVersion
                LastUpdate        = $run.lastStateUpdateDateTime
                MountPoint        = $v.MountPoint
                Encrypted         = ($v.ProtectionStatus -eq 'On' -and $v.VolumeStatus -eq 'FullyEncrypted')
                EncryptionMethod  = $v.EncryptionMethod
                Protectors        = ($v.KeyProtectorTypes -join ',')
                ProtectionStatus  = $v.ProtectionStatus
                VolumeStatus      = $v.VolumeStatus
                EncryptionPercent = $v.EncryptionPercentage
                TpmReady          = $state.Tpm.Ready
                RawOutput         = $output
            })
        }
    }
    $uri = $resp.'@odata.nextLink'
} while ($uri)

$rows | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "Wrote $($rows.Count) volume rows to $OutputCsv"

if ($OutputHtml) {
    $unencrypted = $rows | Where-Object { -not $_.Encrypted }
    $byMethod    = $rows | Where-Object Encrypted | Group-Object EncryptionMethod |
                   Sort-Object Count -Descending |
                   Select-Object @{n='EncryptionMethod';e={$_.Name}}, Count

    $style = @'
<style>
body{font-family:Segoe UI,Arial;margin:24px;color:#222}
h1{font-size:20px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left}
th{background:#f3f3f3}
tr.bad{background:#fff2f2}
</style>
'@
    $summary  = "<h1>BitLocker Inventory Report</h1>" +
                "<p>Generated $(Get-Date -Format o). Total volumes: $($rows.Count). Unencrypted: $($unencrypted.Count).</p>"
    $methods  = $byMethod | ConvertTo-Html -Fragment -PreContent '<h2>Encryption methods in use</h2>'
    $detail   = $rows | Select-Object DeviceName,UserPrincipalName,MountPoint,Encrypted,EncryptionMethod,EncryptionPercent,Protectors,TpmReady,LastUpdate |
                ConvertTo-Html -Fragment -PreContent '<h2>Per-device / per-volume detail</h2>'
    "<html><head>$style</head><body>$summary$methods$detail</body></html>" | Set-Content -Path $OutputHtml -Encoding UTF8
    Write-Host "Wrote HTML report to $OutputHtml"
}
