<#
.SYNOPSIS
    T0 Authentication Security Infrastructure Audit Script

.DESCRIPTION
    This script audits the security of Tier 0 authentication infrastructure in Active Directory:
    - ACLs on Authentication Policy objects
    - ACLs on Authentication Silo objects
    - Rights on msDS-AssignedAuthNPolicy attribute on T0 accounts

    Outputs results in CSV, TXT, and HTML formats with color-coded severity ratings.

.PARAMETER OutputPath
    Path where audit results will be saved. Default: C:\T0_Audit

.PARAMETER T0UserFilter
    Filter for identifying T0 user accounts. Default: {Name -like "*-T0" -or Name -like "*-adm"}

.PARAMETER T0ComputerFilter
    Filter for identifying T0 computer accounts. Default: PKI, ADFS, AADConnect patterns

.PARAMETER IncludeInherited
    Include inherited permissions in the report. Default: $false

.EXAMPLE
    .\Invoke-T0AuthNSecurityAudit.ps1

.EXAMPLE
    .\Invoke-T0AuthNSecurityAudit.ps1 -OutputPath "D:\Audits\T0" -IncludeInherited $true

.NOTES
    Author: T0 Security Team
    Version: 1.0
    Requires: ActiveDirectory module, AD: PSDrive access

    CRITICAL FINDINGS (Red):
    - GenericAll: Full control over object
    - WriteDACL: Can modify permissions
    - WriteOwner: Can take ownership
    - Non-inherited permissions from non-standard principals

    HIGH FINDINGS (Orange):
    - GenericWrite: Can write all properties
    - WriteProperty with broad scope (all properties)

    MEDIUM FINDINGS (Yellow):
    - WriteProperty on specific sensitive attributes
    - ExtendedRight permissions
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = "C:\T0_Audit",

    [Parameter()]
    [switch]$IncludeInherited = $false,

    [Parameter()]
    [string[]]$T0UserPatterns = @("*-T0", "*-adm", "*-admin", "T0-*", "Admin-*"),

    [Parameter()]
    [string[]]$T0ComputerPatterns = @("*PKI*", "*ADFS*", "*AADConnect*", "*AADC*", "*CA*", "*CertAuth*", "*EntraConnect*")
)

#region Configuration

# Standard/Expected principals that typically have permissions (customize as needed)
$Script:StandardPrincipals = @(
    "NT AUTHORITY\\SYSTEM",
    "NT AUTHORITY\\SELF",
    "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS",
    "NT AUTHORITY\\Authenticated Users",
    "BUILTIN\\Administrators",
    "BUILTIN\\Account Operators",
    "BUILTIN\\Server Operators"
)

# Domain-specific standard groups (will be populated dynamically)
$Script:DomainAdminGroups = @()

# GUID mappings for common schema attributes
$Script:AttributeGUIDs = @{
    "00000000-0000-0000-0000-000000000000" = "All Properties"
    "5e6034a2-6db5-4ab6-a2bf-11e06d5cd65a" = "msDS-AssignedAuthNPolicy"
    "d0e8f5b5-5a4e-4bc1-a4f6-2f1c68a5e2a3" = "msDS-AssignedAuthNPolicySilo"
    "bf967a86-0de6-11d0-a285-00aa003049e2" = "Computer"
    "bf967aba-0de6-11d0-a285-00aa003049e2" = "User"
}

# Rights severity classification
$Script:CriticalRights = @("GenericAll", "WriteDacl", "WriteOwner", "GenericWrite")
$Script:HighRights = @("WriteProperty", "Self", "ExtendedRight", "CreateChild", "DeleteChild", "Delete")
$Script:MediumRights = @("ReadProperty", "ReadControl", "ListChildren")

#endregion

#region Helper Functions

function Initialize-AuditEnvironment {
    <#
    .SYNOPSIS
        Initialize the audit environment and validate prerequisites
    #>

    Write-Host "`n" -NoNewline
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "  T0 Authentication Security Infrastructure Audit" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""

    # Check for ActiveDirectory module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory PowerShell module is not installed. Please install RSAT tools."
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    # Verify AD: PSDrive is available
    if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
        throw "AD: PSDrive is not available. Ensure you have the ActiveDirectory module properly configured."
    }

    # Create output directory if it doesn't exist
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Host "[+] Created output directory: $OutputPath" -ForegroundColor Green
    }

    # Get domain information
    $Script:Domain = Get-ADDomain
    $Script:DomainDN = $Script:Domain.DistinguishedName
    $Script:DomainNetBIOS = $Script:Domain.NetBIOSName

    # Populate domain admin groups
    $Script:DomainAdminGroups = @(
        "$($Script:DomainNetBIOS)\\Domain Admins",
        "$($Script:DomainNetBIOS)\\Enterprise Admins",
        "$($Script:DomainNetBIOS)\\Schema Admins",
        "$($Script:DomainNetBIOS)\\Administrators",
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins"
    )

    Write-Host "[+] Connected to domain: $($Script:Domain.DNSRoot)" -ForegroundColor Green
    Write-Host "[+] Output path: $OutputPath" -ForegroundColor Green
    Write-Host ""
}

function Get-SeverityLevel {
    <#
    .SYNOPSIS
        Determine severity level based on rights and inheritance
    #>
    param(
        [string]$Rights,
        [string]$IdentityReference,
        [bool]$IsInherited,
        [string]$ObjectType,
        [string]$AccessControlType
    )

    # Deny permissions are generally protective, lower severity
    if ($AccessControlType -eq "Deny") {
        return "Info"
    }

    # Check if it's a standard/expected principal
    $IsStandardPrincipal = $false
    foreach ($principal in ($Script:StandardPrincipals + $Script:DomainAdminGroups)) {
        if ($IdentityReference -like "*$principal*" -or $IdentityReference -match [regex]::Escape($principal)) {
            $IsStandardPrincipal = $true
            break
        }
    }

    # Non-inherited permissions from non-standard principals are more concerning
    $InheritanceBonus = if (-not $IsInherited -and -not $IsStandardPrincipal) { 1 } else { 0 }

    # Check for critical rights
    foreach ($right in $Script:CriticalRights) {
        if ($Rights -match $right) {
            if ($InheritanceBonus -eq 1) {
                return "Critical"
            }
            return "High"
        }
    }

    # Check for high rights
    foreach ($right in $Script:HighRights) {
        if ($Rights -match $right) {
            # WriteProperty on all properties (GUID 00000000...) is more severe
            if ($right -eq "WriteProperty" -and $ObjectType -eq "00000000-0000-0000-0000-000000000000") {
                return if ($InheritanceBonus -eq 1) { "High" } else { "Medium" }
            }
            return if ($InheritanceBonus -eq 1) { "High" } else { "Medium" }
        }
    }

    return "Low"
}

function Get-FriendlyObjectType {
    <#
    .SYNOPSIS
        Convert GUID to friendly name
    #>
    param([string]$GUID)

    if ([string]::IsNullOrEmpty($GUID)) {
        return "N/A"
    }

    if ($Script:AttributeGUIDs.ContainsKey($GUID)) {
        return $Script:AttributeGUIDs[$GUID]
    }

    # Try to resolve from schema
    try {
        $SchemaPath = "LDAP://CN=Schema,CN=Configuration,$($Script:DomainDN)"
        $Searcher = New-Object DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = [ADSI]$SchemaPath
        $Searcher.Filter = "(schemaIDGUID=\$($GUID -replace '(.{2})(.{2})(.{2})(.{2})-(.{2})(.{2})-(.{2})(.{2})-(.{2})(.{2})-(.{12})', '\4\3\2\1\6\5\8\7\9\10\11'))"
        $Result = $Searcher.FindOne()
        if ($Result) {
            return $Result.Properties["ldapdisplayname"][0]
        }
    }
    catch {
        # Silently continue if resolution fails
    }

    return $GUID
}

function Test-IsNonStandardPrincipal {
    <#
    .SYNOPSIS
        Check if the principal is non-standard (potentially risky)
    #>
    param([string]$IdentityReference)

    foreach ($principal in ($Script:StandardPrincipals + $Script:DomainAdminGroups)) {
        if ($IdentityReference -like "*$principal*" -or $IdentityReference -match [regex]::Escape($principal)) {
            return $false
        }
    }
    return $true
}

#endregion

#region Audit Functions

function Get-AuthNPolicyACLs {
    <#
    .SYNOPSIS
        Audit ACLs on Authentication Policy objects
    #>

    Write-Host "`n[*] Auditing Authentication Policy ACLs..." -ForegroundColor Cyan

    $ConfigNC = (Get-ADRootDSE).configurationNamingContext
    $PolicyContainer = "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,$ConfigNC"

    $Results = [System.Collections.ArrayList]::new()

    # Check if container exists
    try {
        $Policies = Get-ADObject -SearchBase $PolicyContainer -Filter { objectClass -eq "msDS-AuthNPolicy" } -ErrorAction Stop
    }
    catch {
        Write-Host "  [!] Authentication Policies container not found or empty. This may be normal if no policies are configured." -ForegroundColor Yellow
        return $Results
    }

    if (-not $Policies) {
        Write-Host "  [!] No Authentication Policies found." -ForegroundColor Yellow
        return $Results
    }

    $PolicyCount = ($Policies | Measure-Object).Count
    Write-Host "  [+] Found $PolicyCount Authentication Policy objects" -ForegroundColor Green

    foreach ($Policy in $Policies) {
        Write-Host "    [-] Checking policy: $($Policy.Name)" -ForegroundColor Gray

        try {
            $ACL = Get-Acl "AD:\$($Policy.DistinguishedName)"

            foreach ($Access in $ACL.Access) {
                # Skip inherited if not requested
                if ($Access.IsInherited -and -not $IncludeInherited) {
                    continue
                }

                $Severity = Get-SeverityLevel -Rights $Access.ActiveDirectoryRights `
                    -IdentityReference $Access.IdentityReference.ToString() `
                    -IsInherited $Access.IsInherited `
                    -ObjectType $Access.ObjectType.ToString() `
                    -AccessControlType $Access.AccessControlType.ToString()

                $null = $Results.Add([PSCustomObject]@{
                    AuditType           = "AuthN Policy"
                    ObjectName          = $Policy.Name
                    ObjectDN            = $Policy.DistinguishedName
                    IdentityReference   = $Access.IdentityReference.ToString()
                    ActiveDirectoryRights = $Access.ActiveDirectoryRights.ToString()
                    AccessControlType   = $Access.AccessControlType.ToString()
                    ObjectType          = Get-FriendlyObjectType -GUID $Access.ObjectType.ToString()
                    ObjectTypeGUID      = $Access.ObjectType.ToString()
                    InheritedObjectType = Get-FriendlyObjectType -GUID $Access.InheritedObjectType.ToString()
                    IsInherited         = $Access.IsInherited
                    InheritanceFlags    = $Access.InheritanceFlags.ToString()
                    PropagationFlags    = $Access.PropagationFlags.ToString()
                    Severity            = $Severity
                    IsNonStandard       = Test-IsNonStandardPrincipal -IdentityReference $Access.IdentityReference.ToString()
                })
            }
        }
        catch {
            Write-Host "    [!] Error reading ACL for $($Policy.Name): $_" -ForegroundColor Red
        }
    }

    return $Results
}

function Get-AuthNSiloACLs {
    <#
    .SYNOPSIS
        Audit ACLs on Authentication Silo objects
    #>

    Write-Host "`n[*] Auditing Authentication Silo ACLs..." -ForegroundColor Cyan

    $ConfigNC = (Get-ADRootDSE).configurationNamingContext
    $SiloContainer = "CN=AuthN Policy Configuration,CN=Services,$ConfigNC"

    $Results = [System.Collections.ArrayList]::new()

    # Check if container exists
    try {
        $Silos = Get-ADObject -SearchBase $SiloContainer -Filter { objectClass -eq "msDS-AuthNPolicySilo" } -ErrorAction Stop
    }
    catch {
        Write-Host "  [!] Authentication Silos container not found or empty. This may be normal if no silos are configured." -ForegroundColor Yellow
        return $Results
    }

    if (-not $Silos) {
        Write-Host "  [!] No Authentication Silos found." -ForegroundColor Yellow
        return $Results
    }

    $SiloCount = ($Silos | Measure-Object).Count
    Write-Host "  [+] Found $SiloCount Authentication Silo objects" -ForegroundColor Green

    foreach ($Silo in $Silos) {
        Write-Host "    [-] Checking silo: $($Silo.Name)" -ForegroundColor Gray

        try {
            $ACL = Get-Acl "AD:\$($Silo.DistinguishedName)"

            foreach ($Access in $ACL.Access) {
                if ($Access.IsInherited -and -not $IncludeInherited) {
                    continue
                }

                $Severity = Get-SeverityLevel -Rights $Access.ActiveDirectoryRights `
                    -IdentityReference $Access.IdentityReference.ToString() `
                    -IsInherited $Access.IsInherited `
                    -ObjectType $Access.ObjectType.ToString() `
                    -AccessControlType $Access.AccessControlType.ToString()

                $null = $Results.Add([PSCustomObject]@{
                    AuditType           = "AuthN Silo"
                    ObjectName          = $Silo.Name
                    ObjectDN            = $Silo.DistinguishedName
                    IdentityReference   = $Access.IdentityReference.ToString()
                    ActiveDirectoryRights = $Access.ActiveDirectoryRights.ToString()
                    AccessControlType   = $Access.AccessControlType.ToString()
                    ObjectType          = Get-FriendlyObjectType -GUID $Access.ObjectType.ToString()
                    ObjectTypeGUID      = $Access.ObjectType.ToString()
                    InheritedObjectType = Get-FriendlyObjectType -GUID $Access.InheritedObjectType.ToString()
                    IsInherited         = $Access.IsInherited
                    InheritanceFlags    = $Access.InheritanceFlags.ToString()
                    PropagationFlags    = $Access.PropagationFlags.ToString()
                    Severity            = $Severity
                    IsNonStandard       = Test-IsNonStandardPrincipal -IdentityReference $Access.IdentityReference.ToString()
                })
            }
        }
        catch {
            Write-Host "    [!] Error reading ACL for $($Silo.Name): $_" -ForegroundColor Red
        }
    }

    return $Results
}

function Get-T0PolicyAssignmentACLs {
    <#
    .SYNOPSIS
        Audit rights on msDS-AssignedAuthNPolicy attribute on T0 accounts
    #>

    Write-Host "`n[*] Auditing msDS-AssignedAuthNPolicy attribute rights on T0 accounts..." -ForegroundColor Cyan

    $Results = [System.Collections.ArrayList]::new()

    # GUID for msDS-AssignedAuthNPolicy attribute
    $PolicyAttrGUID = "5e6034a2-6db5-4ab6-a2bf-11e06d5cd65a"
    $AllPropertiesGUID = "00000000-0000-0000-0000-000000000000"

    # Collect T0 objects
    $T0Objects = [System.Collections.ArrayList]::new()

    # Domain Controllers
    Write-Host "  [+] Collecting Domain Controllers..." -ForegroundColor Gray
    try {
        $DCs = Get-ADComputer -Filter { PrimaryGroupID -eq 516 } -Properties DistinguishedName, Name
        foreach ($DC in $DCs) {
            $null = $T0Objects.Add([PSCustomObject]@{
                Name = $DC.Name
                DN = $DC.DistinguishedName
                Type = "Domain Controller"
            })
        }
        Write-Host "    Found $($DCs.Count) Domain Controllers" -ForegroundColor Gray
    }
    catch {
        Write-Host "    [!] Error collecting Domain Controllers: $_" -ForegroundColor Red
    }

    # T0 User accounts
    Write-Host "  [+] Collecting T0 User accounts..." -ForegroundColor Gray
    foreach ($pattern in $T0UserPatterns) {
        try {
            $Users = Get-ADUser -Filter "Name -like '$pattern'" -Properties DistinguishedName, Name -ErrorAction SilentlyContinue
            foreach ($User in $Users) {
                # Avoid duplicates
                if ($T0Objects.DN -notcontains $User.DistinguishedName) {
                    $null = $T0Objects.Add([PSCustomObject]@{
                        Name = $User.Name
                        DN = $User.DistinguishedName
                        Type = "T0 User"
                    })
                }
            }
        }
        catch {
            # Silently continue
        }
    }

    # T0 Computer accounts
    Write-Host "  [+] Collecting T0 Computer accounts..." -ForegroundColor Gray
    foreach ($pattern in $T0ComputerPatterns) {
        try {
            $Computers = Get-ADComputer -Filter "Name -like '$pattern'" -Properties DistinguishedName, Name -ErrorAction SilentlyContinue
            foreach ($Computer in $Computers) {
                if ($T0Objects.DN -notcontains $Computer.DistinguishedName) {
                    $null = $T0Objects.Add([PSCustomObject]@{
                        Name = $Computer.Name
                        DN = $Computer.DistinguishedName
                        Type = "T0 Computer"
                    })
                }
            }
        }
        catch {
            # Silently continue
        }
    }

    # Read-Only Domain Controllers
    Write-Host "  [+] Collecting Read-Only Domain Controllers..." -ForegroundColor Gray
    try {
        $RODCs = Get-ADComputer -Filter { PrimaryGroupID -eq 521 } -Properties DistinguishedName, Name -ErrorAction SilentlyContinue
        foreach ($RODC in $RODCs) {
            if ($T0Objects.DN -notcontains $RODC.DistinguishedName) {
                $null = $T0Objects.Add([PSCustomObject]@{
                    Name = $RODC.Name
                    DN = $RODC.DistinguishedName
                    Type = "RODC"
                })
            }
        }
    }
    catch {
        # Silently continue
    }

    Write-Host "  [+] Total T0 objects to audit: $($T0Objects.Count)" -ForegroundColor Green

    # Check each T0 object
    foreach ($T0Object in $T0Objects) {
        Write-Host "    [-] Checking: $($T0Object.Name) ($($T0Object.Type))" -ForegroundColor Gray

        try {
            $ACL = Get-Acl "AD:\$($T0Object.DN)"

            foreach ($Access in $ACL.Access) {
                if ($Access.IsInherited -and -not $IncludeInherited) {
                    continue
                }

                # Check for WriteProperty on msDS-AssignedAuthNPolicy or All Properties
                $RightsString = $Access.ActiveDirectoryRights.ToString()
                $ObjectTypeString = $Access.ObjectType.ToString()

                $IsRelevantRight = $RightsString -match "WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner"
                $IsRelevantAttribute = ($ObjectTypeString -eq $PolicyAttrGUID) -or
                                       ($ObjectTypeString -eq $AllPropertiesGUID) -or
                                       ($RightsString -match "GenericAll|GenericWrite|WriteDacl|WriteOwner")

                if ($IsRelevantRight -and $IsRelevantAttribute) {
                    $Severity = Get-SeverityLevel -Rights $RightsString `
                        -IdentityReference $Access.IdentityReference.ToString() `
                        -IsInherited $Access.IsInherited `
                        -ObjectType $ObjectTypeString `
                        -AccessControlType $Access.AccessControlType.ToString()

                    $null = $Results.Add([PSCustomObject]@{
                        AuditType           = "T0 Policy Assignment"
                        ObjectName          = $T0Object.Name
                        ObjectDN            = $T0Object.DN
                        ObjectCategory      = $T0Object.Type
                        IdentityReference   = $Access.IdentityReference.ToString()
                        ActiveDirectoryRights = $RightsString
                        AccessControlType   = $Access.AccessControlType.ToString()
                        ObjectType          = Get-FriendlyObjectType -GUID $ObjectTypeString
                        ObjectTypeGUID      = $ObjectTypeString
                        InheritedObjectType = Get-FriendlyObjectType -GUID $Access.InheritedObjectType.ToString()
                        IsInherited         = $Access.IsInherited
                        InheritanceFlags    = $Access.InheritanceFlags.ToString()
                        PropagationFlags    = $Access.PropagationFlags.ToString()
                        Severity            = $Severity
                        IsNonStandard       = Test-IsNonStandardPrincipal -IdentityReference $Access.IdentityReference.ToString()
                    })
                }
            }
        }
        catch {
            Write-Host "      [!] Error reading ACL: $_" -ForegroundColor Red
        }
    }

    return $Results
}

#endregion

#region Report Generation Functions

function Export-ToCSV {
    param(
        [Parameter(Mandatory)]
        [System.Collections.ArrayList]$Results,
        [Parameter(Mandatory)]
        [string]$FileName
    )

    $FilePath = Join-Path $OutputPath $FileName
    $Results | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
    Write-Host "  [+] CSV exported: $FilePath" -ForegroundColor Green
}

function Export-ToText {
    param(
        [Parameter(Mandatory)]
        [System.Collections.ArrayList]$Results,
        [Parameter(Mandatory)]
        [string]$FileName
    )

    $FilePath = Join-Path $OutputPath $FileName
    $Results | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "  [+] Text exported: $FilePath" -ForegroundColor Green
}

function Export-ToHTML {
    param(
        [Parameter(Mandatory)]
        [System.Collections.ArrayList]$AllResults,
        [Parameter(Mandatory)]
        [string]$FileName
    )

    $FilePath = Join-Path $OutputPath $FileName
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Count findings by severity
    $CriticalCount = ($AllResults | Where-Object { $_.Severity -eq "Critical" }).Count
    $HighCount = ($AllResults | Where-Object { $_.Severity -eq "High" }).Count
    $MediumCount = ($AllResults | Where-Object { $_.Severity -eq "Medium" }).Count
    $LowCount = ($AllResults | Where-Object { $_.Severity -eq "Low" }).Count
    $InfoCount = ($AllResults | Where-Object { $_.Severity -eq "Info" }).Count

    # Generate HTML
    $HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>T0 Authentication Security Audit Report</title>
    <style>
        :root {
            --critical-color: #dc3545;
            --critical-bg: #f8d7da;
            --high-color: #fd7e14;
            --high-bg: #ffe5d0;
            --medium-color: #ffc107;
            --medium-bg: #fff3cd;
            --low-color: #28a745;
            --low-bg: #d4edda;
            --info-color: #17a2b8;
            --info-bg: #d1ecf1;
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }

        .container {
            max-width: 1800px;
            margin: 0 auto;
        }

        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2em;
        }

        .header .subtitle {
            opacity: 0.8;
            font-size: 1.1em;
        }

        .header .timestamp {
            margin-top: 15px;
            font-size: 0.9em;
            opacity: 0.7;
        }

        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            border-left: 4px solid;
        }

        .summary-card.critical { border-left-color: var(--critical-color); }
        .summary-card.high { border-left-color: var(--high-color); }
        .summary-card.medium { border-left-color: var(--medium-color); }
        .summary-card.low { border-left-color: var(--low-color); }
        .summary-card.info { border-left-color: var(--info-color); }

        .summary-card .count {
            font-size: 2.5em;
            font-weight: bold;
            line-height: 1;
        }

        .summary-card.critical .count { color: var(--critical-color); }
        .summary-card.high .count { color: var(--high-color); }
        .summary-card.medium .count { color: var(--medium-color); }
        .summary-card.low .count { color: var(--low-color); }
        .summary-card.info .count { color: var(--info-color); }

        .summary-card .label {
            margin-top: 5px;
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .section {
            background: white;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }

        .section-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .section-header h2 {
            margin: 0;
            font-size: 1.3em;
            color: #1a1a2e;
        }

        .section-header .badge {
            background: #1a1a2e;
            color: white;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
        }

        .table-container {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9em;
        }

        th {
            background: #1a1a2e;
            color: white;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
            white-space: nowrap;
            position: sticky;
            top: 0;
        }

        td {
            padding: 10px 15px;
            border-bottom: 1px solid #eee;
            vertical-align: top;
        }

        tr:hover {
            background-color: #f8f9fa;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
        }

        .severity-critical {
            background-color: var(--critical-bg);
            color: var(--critical-color);
        }

        .severity-high {
            background-color: var(--high-bg);
            color: var(--high-color);
        }

        .severity-medium {
            background-color: var(--medium-bg);
            color: #856404;
        }

        .severity-low {
            background-color: var(--low-bg);
            color: var(--low-color);
        }

        .severity-info {
            background-color: var(--info-bg);
            color: var(--info-color);
        }

        .row-critical {
            background-color: var(--critical-bg) !important;
        }

        .row-high {
            background-color: var(--high-bg) !important;
        }

        .non-standard {
            color: var(--critical-color);
            font-weight: 600;
        }

        .rights-badge {
            display: inline-block;
            padding: 2px 6px;
            margin: 1px;
            border-radius: 3px;
            font-size: 0.8em;
            background: #e9ecef;
        }

        .rights-critical {
            background: var(--critical-bg);
            color: var(--critical-color);
        }

        .rights-high {
            background: var(--high-bg);
            color: var(--high-color);
        }

        .dn-cell {
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-family: 'Consolas', monospace;
            font-size: 0.85em;
        }

        .dn-cell:hover {
            white-space: normal;
            word-break: break-all;
        }

        .legend {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .legend h3 {
            margin-top: 0;
            color: #1a1a2e;
        }

        .legend-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }

        .legend-item {
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }

        .legend-item .severity-badge {
            flex-shrink: 0;
            min-width: 80px;
            text-align: center;
        }

        .legend-item p {
            margin: 0;
            color: #666;
            font-size: 0.9em;
        }

        .filters {
            background: white;
            border-radius: 10px;
            padding: 15px 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .filters label {
            font-weight: 600;
            color: #1a1a2e;
        }

        .filters select, .filters input {
            padding: 8px 12px;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            font-size: 0.9em;
        }

        .no-findings {
            padding: 40px;
            text-align: center;
            color: #666;
        }

        .no-findings .icon {
            font-size: 3em;
            margin-bottom: 10px;
        }

        @media print {
            body {
                background: white;
            }
            .filters {
                display: none;
            }
            .section {
                break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>T0 Authentication Security Infrastructure Audit</h1>
            <div class="subtitle">ACL Analysis for Authentication Policies, Silos, and T0 Account Policy Assignments</div>
            <div class="timestamp">Generated: $Timestamp | Domain: $($Script:Domain.DNSRoot)</div>
        </div>

        <div class="summary-cards">
            <div class="summary-card critical">
                <div class="count">$CriticalCount</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">$HighCount</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">$MediumCount</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">$LowCount</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">$InfoCount</div>
                <div class="label">Info</div>
            </div>
        </div>

        <div class="legend">
            <h3>Severity Legend</h3>
            <div class="legend-grid">
                <div class="legend-item">
                    <span class="severity-badge severity-critical">Critical</span>
                    <p><strong>Immediate action required.</strong> Non-inherited GenericAll, WriteDACL, or WriteOwner permissions from non-standard principals. These allow complete control over authentication security infrastructure.</p>
                </div>
                <div class="legend-item">
                    <span class="severity-badge severity-high">High</span>
                    <p><strong>Review urgently.</strong> GenericAll, WriteDACL, WriteOwner, or GenericWrite permissions. May allow modification of security policies or takeover of protected accounts.</p>
                </div>
                <div class="legend-item">
                    <span class="severity-badge severity-medium">Medium</span>
                    <p><strong>Review recommended.</strong> WriteProperty permissions on specific attributes or extended rights. Could allow targeted modifications to authentication settings.</p>
                </div>
                <div class="legend-item">
                    <span class="severity-badge severity-low">Low</span>
                    <p><strong>Informational.</strong> Read permissions or other non-modifying access. Generally expected but worth documenting.</p>
                </div>
                <div class="legend-item">
                    <span class="severity-badge severity-info">Info</span>
                    <p><strong>For reference.</strong> Deny permissions (protective) or standard inherited permissions from expected principals.</p>
                </div>
            </div>
        </div>

        <div class="filters">
            <label>Filter by Severity:</label>
            <select id="severityFilter" onchange="filterTable()">
                <option value="all">All Severities</option>
                <option value="critical">Critical Only</option>
                <option value="high">High & Above</option>
                <option value="medium">Medium & Above</option>
            </select>
            <label>Filter by Type:</label>
            <select id="typeFilter" onchange="filterTable()">
                <option value="all">All Types</option>
                <option value="AuthN Policy">AuthN Policy</option>
                <option value="AuthN Silo">AuthN Silo</option>
                <option value="T0 Policy Assignment">T0 Policy Assignment</option>
            </select>
            <label>Search:</label>
            <input type="text" id="searchFilter" onkeyup="filterTable()" placeholder="Search identities, objects...">
        </div>
"@

    # Group results by audit type
    $PolicyResults = $AllResults | Where-Object { $_.AuditType -eq "AuthN Policy" }
    $SiloResults = $AllResults | Where-Object { $_.AuditType -eq "AuthN Silo" }
    $T0Results = $AllResults | Where-Object { $_.AuditType -eq "T0 Policy Assignment" }

    # Function to generate table rows
    function Get-TableRows {
        param($Results, $IncludeCategory = $false)

        $rows = ""
        foreach ($r in ($Results | Sort-Object @{Expression={
            switch ($_.Severity) {
                "Critical" { 0 }
                "High" { 1 }
                "Medium" { 2 }
                "Low" { 3 }
                "Info" { 4 }
                default { 5 }
            }
        }})) {
            $rowClass = switch ($r.Severity) {
                "Critical" { "row-critical" }
                "High" { "row-high" }
                default { "" }
            }

            $severityClass = "severity-$($r.Severity.ToLower())"
            $identityClass = if ($r.IsNonStandard) { "non-standard" } else { "" }

            # Format rights with badges
            $rightsHtml = ""
            $rights = $r.ActiveDirectoryRights -split ", "
            foreach ($right in $rights) {
                $rightClass = "rights-badge"
                if ($right -match "GenericAll|WriteDacl|WriteOwner") {
                    $rightClass += " rights-critical"
                } elseif ($right -match "GenericWrite|WriteProperty") {
                    $rightClass += " rights-high"
                }
                $rightsHtml += "<span class='$rightClass'>$right</span> "
            }

            $categoryCell = if ($IncludeCategory) { "<td>$($r.ObjectCategory)</td>" } else { "" }

            $rows += @"
            <tr class="$rowClass" data-severity="$($r.Severity.ToLower())" data-type="$($r.AuditType)">
                <td><span class="severity-badge $severityClass">$($r.Severity)</span></td>
                <td>$($r.ObjectName)</td>
                $categoryCell
                <td class="$identityClass">$($r.IdentityReference)</td>
                <td>$rightsHtml</td>
                <td>$($r.AccessControlType)</td>
                <td>$($r.ObjectType)</td>
                <td>$($r.IsInherited)</td>
                <td class="dn-cell" title="$($r.ObjectDN)">$($r.ObjectDN)</td>
            </tr>
"@
        }
        return $rows
    }

    # Authentication Policies section
    $HTML += @"
        <div class="section">
            <div class="section-header">
                <h2>Authentication Policy ACLs</h2>
                <span class="badge">$($PolicyResults.Count) findings</span>
            </div>
            <div class="table-container">
"@

    if ($PolicyResults.Count -gt 0) {
        $HTML += @"
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Policy Name</th>
                            <th>Identity</th>
                            <th>Rights</th>
                            <th>Type</th>
                            <th>Object Type</th>
                            <th>Inherited</th>
                            <th>Distinguished Name</th>
                        </tr>
                    </thead>
                    <tbody>
                        $(Get-TableRows -Results $PolicyResults)
                    </tbody>
                </table>
"@
    } else {
        $HTML += '<div class="no-findings"><div class="icon">✓</div>No Authentication Policies found or no non-inherited ACLs detected.</div>'
    }

    $HTML += "</div></div>"

    # Authentication Silos section
    $HTML += @"
        <div class="section">
            <div class="section-header">
                <h2>Authentication Silo ACLs</h2>
                <span class="badge">$($SiloResults.Count) findings</span>
            </div>
            <div class="table-container">
"@

    if ($SiloResults.Count -gt 0) {
        $HTML += @"
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Silo Name</th>
                            <th>Identity</th>
                            <th>Rights</th>
                            <th>Type</th>
                            <th>Object Type</th>
                            <th>Inherited</th>
                            <th>Distinguished Name</th>
                        </tr>
                    </thead>
                    <tbody>
                        $(Get-TableRows -Results $SiloResults)
                    </tbody>
                </table>
"@
    } else {
        $HTML += '<div class="no-findings"><div class="icon">✓</div>No Authentication Silos found or no non-inherited ACLs detected.</div>'
    }

    $HTML += "</div></div>"

    # T0 Policy Assignment section
    $HTML += @"
        <div class="section">
            <div class="section-header">
                <h2>T0 Account Policy Assignment Rights (msDS-AssignedAuthNPolicy)</h2>
                <span class="badge">$($T0Results.Count) findings</span>
            </div>
            <div class="table-container">
"@

    if ($T0Results.Count -gt 0) {
        $HTML += @"
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Object Name</th>
                            <th>Category</th>
                            <th>Identity</th>
                            <th>Rights</th>
                            <th>Type</th>
                            <th>Object Type</th>
                            <th>Inherited</th>
                            <th>Distinguished Name</th>
                        </tr>
                    </thead>
                    <tbody>
                        $(Get-TableRows -Results $T0Results -IncludeCategory $true)
                    </tbody>
                </table>
"@
    } else {
        $HTML += '<div class="no-findings"><div class="icon">✓</div>No T0 accounts found matching the specified patterns or no relevant ACLs detected.</div>'
    }

    $HTML += @"
            </div>
        </div>

        <script>
            function filterTable() {
                const severityFilter = document.getElementById('severityFilter').value;
                const typeFilter = document.getElementById('typeFilter').value;
                const searchFilter = document.getElementById('searchFilter').value.toLowerCase();

                const rows = document.querySelectorAll('tbody tr');

                rows.forEach(row => {
                    const severity = row.getAttribute('data-severity');
                    const type = row.getAttribute('data-type');
                    const text = row.textContent.toLowerCase();

                    let showSeverity = true;
                    if (severityFilter === 'critical') {
                        showSeverity = severity === 'critical';
                    } else if (severityFilter === 'high') {
                        showSeverity = severity === 'critical' || severity === 'high';
                    } else if (severityFilter === 'medium') {
                        showSeverity = severity === 'critical' || severity === 'high' || severity === 'medium';
                    }

                    const showType = typeFilter === 'all' || type === typeFilter;
                    const showSearch = searchFilter === '' || text.includes(searchFilter);

                    row.style.display = (showSeverity && showType && showSearch) ? '' : 'none';
                });
            }
        </script>
    </div>
</body>
</html>
"@

    $HTML | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "  [+] HTML exported: $FilePath" -ForegroundColor Green
}

#endregion

#region Main Execution

try {
    # Initialize
    Initialize-AuditEnvironment

    # Run all audits
    $AllResults = [System.Collections.ArrayList]::new()

    $PolicyACLs = Get-AuthNPolicyACLs
    foreach ($item in $PolicyACLs) { $null = $AllResults.Add($item) }

    $SiloACLs = Get-AuthNSiloACLs
    foreach ($item in $SiloACLs) { $null = $AllResults.Add($item) }

    $T0ACLs = Get-T0PolicyAssignmentACLs
    foreach ($item in $T0ACLs) { $null = $AllResults.Add($item) }

    # Export results
    Write-Host "`n[*] Exporting results..." -ForegroundColor Cyan

    if ($AllResults.Count -gt 0) {
        # Export all results combined
        Export-ToCSV -Results $AllResults -FileName "T0_AuthN_Security_Audit_All.csv"
        Export-ToText -Results $AllResults -FileName "T0_AuthN_Security_Audit_All.txt"
        Export-ToHTML -AllResults $AllResults -FileName "T0_AuthN_Security_Audit_Report.html"

        # Export individual reports
        if ($PolicyACLs.Count -gt 0) {
            Export-ToCSV -Results ([System.Collections.ArrayList]$PolicyACLs) -FileName "AuthN_Policy_ACLs.csv"
        }
        if ($SiloACLs.Count -gt 0) {
            Export-ToCSV -Results ([System.Collections.ArrayList]$SiloACLs) -FileName "AuthN_Silo_ACLs.csv"
        }
        if ($T0ACLs.Count -gt 0) {
            Export-ToCSV -Results ([System.Collections.ArrayList]$T0ACLs) -FileName "T0_PolicyAssignment_ACLs.csv"
        }

        # Summary
        Write-Host "`n" -NoNewline
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host "  Audit Summary" -ForegroundColor Cyan
        Write-Host "=" * 70 -ForegroundColor Cyan

        $CriticalCount = ($AllResults | Where-Object { $_.Severity -eq "Critical" }).Count
        $HighCount = ($AllResults | Where-Object { $_.Severity -eq "High" }).Count
        $MediumCount = ($AllResults | Where-Object { $_.Severity -eq "Medium" }).Count
        $LowCount = ($AllResults | Where-Object { $_.Severity -eq "Low" }).Count

        Write-Host ""
        Write-Host "  Total Findings: $($AllResults.Count)" -ForegroundColor White
        if ($CriticalCount -gt 0) {
            Write-Host "  Critical: $CriticalCount" -ForegroundColor Red
        } else {
            Write-Host "  Critical: 0" -ForegroundColor Green
        }
        if ($HighCount -gt 0) {
            Write-Host "  High: $HighCount" -ForegroundColor DarkYellow
        } else {
            Write-Host "  High: 0" -ForegroundColor Green
        }
        Write-Host "  Medium: $MediumCount" -ForegroundColor Yellow
        Write-Host "  Low: $LowCount" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Reports saved to: $OutputPath" -ForegroundColor Green
        Write-Host ""
    }
    else {
        Write-Host "`n[!] No findings to export. This could mean:" -ForegroundColor Yellow
        Write-Host "    - No Authentication Policies or Silos are configured" -ForegroundColor Yellow
        Write-Host "    - No T0 accounts match the specified patterns" -ForegroundColor Yellow
        Write-Host "    - All permissions are inherited (use -IncludeInherited to see them)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}

#endregion
