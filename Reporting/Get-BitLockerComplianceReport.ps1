<#
.SYNOPSIS
    Generates a detailed BitLocker compliance report from Intune Remediations.
.DESCRIPTION
    Queries Microsoft Graph for the device run states of the
    Detect-BitLockerCompliance.ps1 detection script, extracts the
    BITLOCKER_DIAG={...json...} payload from the pre-remediation detection
    output of each device, and produces a CSV (and optional HTML) report
    with one row per device including every diagnostic field.

    Permissions (delegated or app-only): DeviceManagementManagedDevices.Read.All,
    DeviceManagementConfiguration.Read.All.
.PARAMETER ScriptId
    The Id (GUID) of the Intune Remediation (deviceHealthScript) that runs
    Detect-BitLockerCompliance.ps1.
.PARAMETER OutputCsv
    Path of the CSV file to produce.
.PARAMETER OutputHtml
    Optional path of an HTML summary report.
.EXAMPLE
    Connect-MgGraph -Scopes DeviceManagementManagedDevices.Read.All,DeviceManagementConfiguration.Read.All
    .\Get-BitLockerComplianceReport.ps1 -ScriptId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -OutputCsv .\bitlocker.csv -OutputHtml .\bitlocker.html
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
        $output = "$($run.preRemediationDetectionScriptOutput)"
        $diag = $null
        $match = [regex]::Match($output, 'BITLOCKER_DIAG=(\{.*\})')
        if ($match.Success) {
            try { $diag = $match.Groups[1].Value | ConvertFrom-Json } catch { }
        }
        $rows.Add([pscustomobject]@{
            DeviceName                   = $run.managedDevice.deviceName
            UserPrincipalName            = $run.managedDevice.userPrincipalName
            OSVersion                    = $run.managedDevice.osVersion
            DetectionState               = $run.detectionState           # success | fail | pending | error | scriptError
            LastStateUpdateDateTime      = $run.lastStateUpdateDateTime
            MountPoint                   = $diag.MountPoint
            ProtectionStatus             = $diag.ProtectionStatus
            VolumeStatus                 = $diag.VolumeStatus
            EncryptionMethod             = $diag.EncryptionMethod
            EncryptionPercentage         = $diag.EncryptionPercentage
            KeyProtectorTypes            = ($diag.KeyProtectorTypes -join ',')
            RecoveryKeyEscrowedInEntraId = $diag.RecoveryKeyEscrowedInEntraId
            EntraIdJoined                = $diag.EntraIdJoined
            TpmReady                     = $diag.Tpm.Ready
            NonComplianceReasons         = ($diag.NonComplianceReasons -join ' | ')
            RawOutput                    = $output
        })
    }
    $uri = $resp.'@odata.nextLink'
} while ($uri)

$rows | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "Wrote $($rows.Count) rows to $OutputCsv"

if ($OutputHtml) {
    $nonCompliant = $rows | Where-Object { $_.DetectionState -eq 'fail' -or $_.NonComplianceReasons }
    $byReason = $nonCompliant |
        ForEach-Object { ($_.NonComplianceReasons -split '\s\|\s') } |
        Where-Object { $_ } |
        Group-Object | Sort-Object Count -Descending |
        Select-Object @{n='Reason';e={$_.Name}}, Count

    $style = @'
<style>
body{font-family:Segoe UI,Arial;margin:24px;color:#222}
h1{font-size:20px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f3f3f3}
tr.fail{background:#fff2f2}
</style>
'@
    $summary = "<h1>BitLocker Compliance Report</h1>" +
               "<p>Generated $(Get-Date -Format o). Total devices: $($rows.Count). Non-compliant: $($nonCompliant.Count).</p>"
    $reasonHtml = $byReason | ConvertTo-Html -Fragment -PreContent '<h2>Top non-compliance reasons</h2>'
    $detailHtml = $rows | Select-Object DeviceName,UserPrincipalName,DetectionState,ProtectionStatus,VolumeStatus,EncryptionMethod,EncryptionPercentage,KeyProtectorTypes,RecoveryKeyEscrowedInEntraId,TpmReady,NonComplianceReasons |
        ConvertTo-Html -Fragment -PreContent '<h2>Per-device detail</h2>'
    "<html><head>$style</head><body>$summary$reasonHtml$detailHtml</body></html>" | Set-Content -Path $OutputHtml -Encoding UTF8
    Write-Host "Wrote HTML report to $OutputHtml"
}
