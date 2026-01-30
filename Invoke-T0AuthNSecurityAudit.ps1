[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Path where audit results will be saved")]
    [string]$OutputPath = "C:\T0_Audit",

    [Parameter(HelpMessage = "Include inherited permissions in ACL audit")]
    [switch]$IncludeInherited = $false,

    [Parameter(HelpMessage = "Additional privileged groups to include (array of group names)")]
    [string[]]$AdditionalPrivilegedGroups = @()
)

<#
.SYNOPSIS
    T0 Authentication Security Infrastructure Audit Script

.DESCRIPTION
    This script performs a comprehensive audit of Tier 0 authentication security:

    Phase 1: Identity & Perimeter Discovery
    - Identifies high-privilege users (DA, EA, SA members)
    - Locates their assigned Authentication Policies and Silos
    - Maps the infrastructure groups (allowed sign-on targets)

    Phase 2: Security Object ACL Audit
    - Audits ACLs on discovered T0 Policies and Silos
    - Uses contextual severity classification (SYSTEM on DC = Info, not Critical)

    Phase 3: Gap Analysis
    - Checks if all privileged accounts have policy assignments
    - Verifies DCs are in the T0 infrastructure group

    Phase 4: Access Map (Reachability Report)
    - Lists all computers where T0 admins can sign on
    - Flags non-DCs in T0 groups as potential "T0 Pollution"

    Phase 5: Report Generation
    - ACL Trust Report (unauthorized managers only)
    - Identity & Infrastructure Gaps
    - Effective Perimeter Map

.PARAMETER OutputPath
    Path where audit results will be saved. Default: C:\T0_Audit

.PARAMETER IncludeInherited
    Include inherited permissions in the ACL audit. Default: $false

.PARAMETER AdditionalPrivilegedGroups
    Additional privileged groups to include in the audit.

.EXAMPLE
    .\Invoke-T0AuthNSecurityAudit.ps1
    Run full T0 security audit with default settings.

.EXAMPLE
    .\Invoke-T0AuthNSecurityAudit.ps1 -OutputPath "D:\Audits"
    Run audit with custom output path.

.EXAMPLE
    .\Invoke-T0AuthNSecurityAudit.ps1 -AdditionalPrivilegedGroups @("SQL Admins", "Exchange Admins")
    Include additional groups in the privileged account analysis.

.NOTES
    Author: T0 Security Team
    Version: 2.0
    Requires: ActiveDirectory module, AD: PSDrive access

    Severity Classification:
    - CRITICAL: Unauthorized identity with modify rights on T0 objects
    - WARNING: T0 Pollution (non-DC in T0 server group)
    - INFO: Expected permissions (SYSTEM, Domain Admins, Enterprise Admins)
#>

#region Script Variables

# Well-known SIDs
$Script:WellKnownSIDs = @{
    "S-1-5-18"     = "NT AUTHORITY\SYSTEM"
    "S-1-5-11"     = "NT AUTHORITY\Authenticated Users"
    "S-1-1-0"      = "Everyone"
    "S-1-5-10"     = "NT AUTHORITY\SELF"
}

# Domain-specific variables (populated at runtime)
$Script:DomainInfo = $null
$Script:DomainSID = $null
$Script:ConfigNC = $null

# T0 Discovery Results
$Script:T0Policies = [System.Collections.ArrayList]::new()
$Script:T0Silos = [System.Collections.ArrayList]::new()
$Script:T0InfrastructureGroups = [System.Collections.ArrayList]::new()
$Script:T0InfrastructureComputers = [System.Collections.ArrayList]::new()
$Script:PrivilegedUsers = [System.Collections.ArrayList]::new()
$Script:DomainControllers = [System.Collections.ArrayList]::new()

#endregion

#region Helper Functions

function Initialize-AuditEnvironment {
    <#
    .SYNOPSIS
        Initialize the audit environment and validate prerequisites
    #>

    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "  T0 Authentication Security Infrastructure Audit v2.0" -ForegroundColor Cyan
    Write-Host "  Dynamic Discovery Mode - No Static Filters" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""

    # Check for ActiveDirectory module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory PowerShell module is not installed. Please install RSAT tools."
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    # Verify AD: PSDrive is available
    if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
        throw "AD: PSDrive is not available. Ensure the ActiveDirectory module is properly configured."
    }

    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Host "[+] Created output directory: $OutputPath" -ForegroundColor Green
    }

    # Get domain information
    $Script:DomainInfo = Get-ADDomain
    $Script:DomainSID = $Script:DomainInfo.DomainSID.Value
    $Script:ConfigNC = (Get-ADRootDSE).configurationNamingContext

    Write-Host "[+] Connected to domain: $($Script:DomainInfo.DNSRoot)" -ForegroundColor Green
    Write-Host "[+] Domain SID: $Script:DomainSID" -ForegroundColor Green
    Write-Host "[+] Output path: $OutputPath" -ForegroundColor Green
    Write-Host ""
}

function Test-IsExpectedT0Manager {
    <#
    .SYNOPSIS
        Check if an identity is an expected T0 manager (should have permissions)
    #>
    param(
        [string]$IdentityReference,
        [string]$IdentitySID
    )

    # SYSTEM is always expected
    if ($IdentitySID -eq "S-1-5-18" -or $IdentityReference -match "NT AUTHORITY\\SYSTEM") {
        return @{ IsExpected = $true; Reason = "SYSTEM - Required for AD operations" }
    }

    # Enterprise Admins
    if ($IdentitySID -eq "$Script:DomainSID-519" -or $IdentityReference -match "Enterprise Admins") {
        return @{ IsExpected = $true; Reason = "Enterprise Admins - Designated T0 managers" }
    }

    # Domain Admins
    if ($IdentitySID -eq "$Script:DomainSID-512" -or $IdentityReference -match "Domain Admins") {
        return @{ IsExpected = $true; Reason = "Domain Admins - Designated T0 managers" }
    }

    # Schema Admins
    if ($IdentitySID -eq "$Script:DomainSID-518" -or $IdentityReference -match "Schema Admins") {
        return @{ IsExpected = $true; Reason = "Schema Admins - Designated T0 managers" }
    }

    # BUILTIN\Administrators
    if ($IdentitySID -eq "S-1-5-32-544" -or $IdentityReference -match "BUILTIN\\Administrators") {
        return @{ IsExpected = $true; Reason = "Built-in Administrators" }
    }

    return @{ IsExpected = $false; Reason = "Unexpected identity" }
}

function Test-IsReadOnlyPermission {
    <#
    .SYNOPSIS
        Check if permission is read-only (non-modifying)
    #>
    param([string]$Rights)

    $readOnlyRights = @("ReadProperty", "ReadControl", "ListChildren", "ListObject", "GenericRead")

    foreach ($right in $readOnlyRights) {
        if ($Rights -match $right -and $Rights -notmatch "Write|GenericAll|Delete|Create") {
            return $true
        }
    }
    return $false
}

function Get-SeverityLevel {
    <#
    .SYNOPSIS
        Determine severity level with contextual awareness
    #>
    param(
        [string]$Rights,
        [string]$IdentityReference,
        [string]$IdentitySID,
        [string]$AccessControlType
    )

    # Deny permissions are protective
    if ($AccessControlType -eq "Deny") {
        return @{ Severity = "Info"; Reason = "Deny ACE (protective)" }
    }

    # Check if read-only
    if (Test-IsReadOnlyPermission -Rights $Rights) {
        return @{ Severity = "Info"; Reason = "Read-only permission" }
    }

    # Check if expected T0 manager
    $expectedCheck = Test-IsExpectedT0Manager -IdentityReference $IdentityReference -IdentitySID $IdentitySID
    if ($expectedCheck.IsExpected) {
        return @{ Severity = "Healthy"; Reason = $expectedCheck.Reason }
    }

    # Check for dangerous rights from unexpected identities
    $dangerousRights = @("GenericAll", "WriteDacl", "WriteOwner", "GenericWrite", "WriteProperty")
    foreach ($dangerousRight in $dangerousRights) {
        if ($Rights -match $dangerousRight) {
            return @{ Severity = "Critical"; Reason = "Unauthorized modify rights - Privilege escalation path!" }
        }
    }

    return @{ Severity = "Medium"; Reason = "Non-standard permission" }
}

function Get-GroupFromSDDL {
    <#
    .SYNOPSIS
        Extract group SIDs from an SDDL condition string
    #>
    param([string]$SDDLCondition)

    $groups = [System.Collections.ArrayList]::new()

    if ([string]::IsNullOrEmpty($SDDLCondition)) {
        return $groups
    }

    # Pattern to match SIDs in SDDL
    $sidPattern = 'S-1-[0-9-]+'
    $matches = [regex]::Matches($SDDLCondition, $sidPattern)

    foreach ($match in $matches) {
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($match.Value)
            $ntAccount = $sid.Translate([System.Security.Principal.NTAccount])
            $null = $groups.Add([PSCustomObject]@{
                SID = $match.Value
                Name = $ntAccount.Value
            })
        }
        catch {
            $null = $groups.Add([PSCustomObject]@{
                SID = $match.Value
                Name = "(Unable to resolve)"
            })
        }
    }

    return $groups
}

#endregion

#region Phase 1: Identity & Perimeter Discovery

function Invoke-Phase1Discovery {
    <#
    .SYNOPSIS
        Phase 1: Identify high-privilege users and their security boundaries
    #>

    Write-Host "=" * 80 -ForegroundColor Yellow
    Write-Host "  PHASE 1: Identity & Perimeter Discovery" -ForegroundColor Yellow
    Write-Host "=" * 80 -ForegroundColor Yellow
    Write-Host ""

    # Step 1.1: Identify all Domain Controllers
    Write-Host "[Phase 1.1] Identifying Domain Controllers..." -ForegroundColor Cyan
    try {
        $dcs = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521 } `
            -Properties Name, DistinguishedName, DNSHostName, OperatingSystem, PrimaryGroupID, `
                        "msDS-AssignedAuthNPolicy", "msDS-AssignedAuthNPolicySilo"

        foreach ($dc in $dcs) {
            $dcType = if ($dc.PrimaryGroupID -eq 516) { "RWDC" } else { "RODC" }
            $null = $Script:DomainControllers.Add([PSCustomObject]@{
                Name = $dc.Name
                DN = $dc.DistinguishedName
                DNSHostName = $dc.DNSHostName
                OperatingSystem = $dc.OperatingSystem
                Type = $dcType
                AuthNPolicy = $dc."msDS-AssignedAuthNPolicy"
                AuthNPolicySilo = $dc."msDS-AssignedAuthNPolicySilo"
            })
        }
        Write-Host "    Found $($Script:DomainControllers.Count) Domain Controllers" -ForegroundColor Green
    }
    catch {
        Write-Host "    [!] Error collecting Domain Controllers: $_" -ForegroundColor Red
    }

    # Step 1.2: Identify High-Privilege Users (The "Big Three" + additional)
    Write-Host "[Phase 1.2] Identifying High-Privilege Users..." -ForegroundColor Cyan

    $privilegedGroups = @(
        @{ Name = "Domain Admins"; Criticality = "Critical" }
        @{ Name = "Enterprise Admins"; Criticality = "Critical" }
        @{ Name = "Schema Admins"; Criticality = "Critical" }
    )

    # Add user-specified groups
    foreach ($additionalGroup in $AdditionalPrivilegedGroups) {
        $privilegedGroups += @{ Name = $additionalGroup; Criticality = "High" }
    }

    $processedUsers = @{}

    foreach ($group in $privilegedGroups) {
        Write-Host "    Checking: $($group.Name)" -ForegroundColor Gray
        try {
            $members = Get-ADGroupMember -Identity $group.Name -Recursive -ErrorAction Stop |
                       Where-Object { $_.objectClass -eq "user" }

            foreach ($member in $members) {
                if ($processedUsers.ContainsKey($member.distinguishedName)) {
                    # Update group membership
                    $idx = $Script:PrivilegedUsers.DN.IndexOf($member.distinguishedName)
                    if ($idx -ge 0) {
                        $Script:PrivilegedUsers[$idx].MemberOf += ", $($group.Name)"
                    }
                    continue
                }

                $processedUsers[$member.distinguishedName] = $true

                # Get full user details with AuthN attributes
                $userDetails = Get-ADUser -Identity $member.distinguishedName `
                    -Properties Name, SamAccountName, DistinguishedName, Enabled, `
                                "msDS-AssignedAuthNPolicy", "msDS-AssignedAuthNPolicySilo"

                $null = $Script:PrivilegedUsers.Add([PSCustomObject]@{
                    Name = $userDetails.Name
                    SamAccountName = $userDetails.SamAccountName
                    DN = $userDetails.DistinguishedName
                    Enabled = $userDetails.Enabled
                    MemberOf = $group.Name
                    Criticality = $group.Criticality
                    AuthNPolicy = $userDetails."msDS-AssignedAuthNPolicy"
                    AuthNPolicySilo = $userDetails."msDS-AssignedAuthNPolicySilo"
                })
            }
        }
        catch {
            Write-Host "      [!] Group not found or not accessible: $($group.Name)" -ForegroundColor Yellow
        }
    }
    Write-Host "    Found $($Script:PrivilegedUsers.Count) unique privileged users" -ForegroundColor Green

    # Step 1.3: Discover T0 Policies and Silos from privileged user assignments
    Write-Host "[Phase 1.3] Discovering T0 Security Boundaries (Policies & Silos)..." -ForegroundColor Cyan

    $discoveredPolicies = @{}
    $discoveredSilos = @{}

    foreach ($user in $Script:PrivilegedUsers) {
        # Track policies
        if (-not [string]::IsNullOrEmpty($user.AuthNPolicy)) {
            if (-not $discoveredPolicies.ContainsKey($user.AuthNPolicy)) {
                $discoveredPolicies[$user.AuthNPolicy] = [System.Collections.ArrayList]::new()
            }
            $null = $discoveredPolicies[$user.AuthNPolicy].Add($user.Name)
        }

        # Track silos
        if (-not [string]::IsNullOrEmpty($user.AuthNPolicySilo)) {
            if (-not $discoveredSilos.ContainsKey($user.AuthNPolicySilo)) {
                $discoveredSilos[$user.AuthNPolicySilo] = [System.Collections.ArrayList]::new()
            }
            $null = $discoveredSilos[$user.AuthNPolicySilo].Add($user.Name)
        }
    }

    # Get full details for discovered policies
    foreach ($policyDN in $discoveredPolicies.Keys) {
        try {
            $policy = Get-ADObject -Identity $policyDN `
                -Properties Name, DistinguishedName, Description, `
                            "msDS-UserAllowedToAuthenticateFrom", "msDS-UserAllowedToAuthenticateTo", `
                            "msDS-UserTGTLifetime", "msDS-ComputerAllowedToAuthenticateTo", `
                            "msDS-ServiceAllowedToAuthenticateFrom", "msDS-ServiceAllowedToAuthenticateTo"

            $null = $Script:T0Policies.Add([PSCustomObject]@{
                Name = $policy.Name
                DN = $policy.DistinguishedName
                Description = $policy.Description
                UserAllowedToAuthenticateFrom = $policy."msDS-UserAllowedToAuthenticateFrom"
                UserAllowedToAuthenticateTo = $policy."msDS-UserAllowedToAuthenticateTo"
                UserTGTLifetime = $policy."msDS-UserTGTLifetime"
                AssignedUsers = $discoveredPolicies[$policyDN]
                DiscoverySource = "Privileged User Assignment"
            })
        }
        catch {
            Write-Host "      [!] Could not read policy: $policyDN" -ForegroundColor Yellow
        }
    }
    Write-Host "    Found $($Script:T0Policies.Count) T0 Authentication Policies" -ForegroundColor Green

    # Get full details for discovered silos
    foreach ($siloDN in $discoveredSilos.Keys) {
        try {
            $silo = Get-ADObject -Identity $siloDN `
                -Properties Name, DistinguishedName, Description, `
                            "msDS-AuthNPolicySiloMembers", "msDS-AuthNPolicySiloEnforced", `
                            "msDS-ComputerAuthNPolicy", "msDS-ServiceAuthNPolicy", "msDS-UserAuthNPolicy"

            $null = $Script:T0Silos.Add([PSCustomObject]@{
                Name = $silo.Name
                DN = $silo.DistinguishedName
                Description = $silo.Description
                IsEnforced = $silo."msDS-AuthNPolicySiloEnforced"
                Members = $silo."msDS-AuthNPolicySiloMembers"
                ComputerPolicy = $silo."msDS-ComputerAuthNPolicy"
                ServicePolicy = $silo."msDS-ServiceAuthNPolicy"
                UserPolicy = $silo."msDS-UserAuthNPolicy"
                AssignedUsers = $discoveredSilos[$siloDN]
                DiscoverySource = "Privileged User Assignment"
            })

            # IMPORTANT: Also discover policies linked to this Silo
            # These are T0 policies even if not directly assigned to users
            $siloPolicies = @($silo."msDS-UserAuthNPolicy", $silo."msDS-ComputerAuthNPolicy", $silo."msDS-ServiceAuthNPolicy") |
                            Where-Object { -not [string]::IsNullOrEmpty($_) }

            foreach ($policyDN in $siloPolicies) {
                # Check if we already have this policy
                $existingPolicy = $Script:T0Policies | Where-Object { $_.DN -eq $policyDN }
                if (-not $existingPolicy) {
                    try {
                        $policy = Get-ADObject -Identity $policyDN `
                            -Properties Name, DistinguishedName, Description, `
                                        "msDS-UserAllowedToAuthenticateFrom", "msDS-UserAllowedToAuthenticateTo", `
                                        "msDS-UserTGTLifetime", "msDS-ComputerAllowedToAuthenticateTo", `
                                        "msDS-ServiceAllowedToAuthenticateFrom", "msDS-ServiceAllowedToAuthenticateTo"

                        $null = $Script:T0Policies.Add([PSCustomObject]@{
                            Name = $policy.Name
                            DN = $policy.DistinguishedName
                            Description = $policy.Description
                            UserAllowedToAuthenticateFrom = $policy."msDS-UserAllowedToAuthenticateFrom"
                            UserAllowedToAuthenticateTo = $policy."msDS-UserAllowedToAuthenticateTo"
                            UserTGTLifetime = $policy."msDS-UserTGTLifetime"
                            AssignedUsers = @()
                            DiscoverySource = "Linked to Silo: $($silo.Name)"
                        })
                        Write-Host "      Discovered policy from silo: $($policy.Name)" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "      [!] Could not read policy linked to silo: $policyDN" -ForegroundColor Yellow
                    }
                }
            }
        }
        catch {
            Write-Host "      [!] Could not read silo: $siloDN" -ForegroundColor Yellow
        }
    }
    Write-Host "    Found $($Script:T0Silos.Count) T0 Authentication Silos" -ForegroundColor Green
    Write-Host "    Found $($Script:T0Policies.Count) T0 Authentication Policies (including silo-linked)" -ForegroundColor Green

    # Step 1.4: Extract Infrastructure Groups from Policies
    Write-Host "[Phase 1.4] Extracting T0 Infrastructure Groups from Policies..." -ForegroundColor Cyan

    foreach ($policy in $Script:T0Policies) {
        $userAllowedFrom = $policy.UserAllowedToAuthenticateFrom

        if (-not [string]::IsNullOrEmpty($userAllowedFrom)) {
            Write-Host "    Policy '$($policy.Name)' has User Sign-On restriction" -ForegroundColor Gray

            # Extract groups from the SDDL condition
            $groups = Get-GroupFromSDDL -SDDLCondition $userAllowedFrom

            foreach ($group in $groups) {
                # Check if this is a group (not a built-in SID)
                if ($group.SID -notmatch "^S-1-5-[0-9]+$" -and $group.SID -notmatch "^S-1-1-0$") {
                    try {
                        # Try to get as AD group
                        $adGroup = Get-ADGroup -Identity $group.SID -Properties Members -ErrorAction SilentlyContinue
                        if ($adGroup) {
                            $null = $Script:T0InfrastructureGroups.Add([PSCustomObject]@{
                                Name = $adGroup.Name
                                DN = $adGroup.DistinguishedName
                                SID = $group.SID
                                SourcePolicy = $policy.Name
                            })
                            Write-Host "      Found infrastructure group: $($adGroup.Name)" -ForegroundColor Green
                        }
                    }
                    catch {
                        # Not a group or can't be resolved
                    }
                }
            }
        }
    }
    Write-Host "    Found $($Script:T0InfrastructureGroups.Count) T0 Infrastructure Groups" -ForegroundColor Green

    # Step 1.5: Get all computers in T0 Infrastructure Groups
    Write-Host "[Phase 1.5] Mapping T0 Infrastructure Computers..." -ForegroundColor Cyan

    $processedComputers = @{}

    foreach ($group in $Script:T0InfrastructureGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group.DN -Recursive -ErrorAction SilentlyContinue |
                       Where-Object { $_.objectClass -eq "computer" }

            foreach ($member in $members) {
                if ($processedComputers.ContainsKey($member.distinguishedName)) {
                    continue
                }
                $processedComputers[$member.distinguishedName] = $true

                $computer = Get-ADComputer -Identity $member.distinguishedName `
                    -Properties Name, DistinguishedName, DNSHostName, OperatingSystem, PrimaryGroupID

                $isDC = ($computer.PrimaryGroupID -eq 516 -or $computer.PrimaryGroupID -eq 521)

                $null = $Script:T0InfrastructureComputers.Add([PSCustomObject]@{
                    Name = $computer.Name
                    DN = $computer.DistinguishedName
                    DNSHostName = $computer.DNSHostName
                    OperatingSystem = $computer.OperatingSystem
                    IsDomainController = $isDC
                    SourceGroup = $group.Name
                })
            }
        }
        catch {
            Write-Host "      [!] Error reading group members: $($group.Name)" -ForegroundColor Yellow
        }
    }
    Write-Host "    Found $($Script:T0InfrastructureComputers.Count) computers in T0 Infrastructure Groups" -ForegroundColor Green

    Write-Host ""
    Write-Host "[Phase 1 Complete] Discovery Summary:" -ForegroundColor Green
    Write-Host "    Domain Controllers:      $($Script:DomainControllers.Count)" -ForegroundColor White
    Write-Host "    Privileged Users:        $($Script:PrivilegedUsers.Count)" -ForegroundColor White
    Write-Host "    T0 Policies:             $($Script:T0Policies.Count)" -ForegroundColor White
    Write-Host "    T0 Silos:                $($Script:T0Silos.Count)" -ForegroundColor White
    Write-Host "    T0 Infrastructure Groups: $($Script:T0InfrastructureGroups.Count)" -ForegroundColor White
    Write-Host "    T0 Infrastructure Computers: $($Script:T0InfrastructureComputers.Count)" -ForegroundColor White
    Write-Host ""
}

#endregion

#region Phase 2: Security Object ACL Audit

function Invoke-Phase2ACLAudit {
    <#
    .SYNOPSIS
        Phase 2: Audit ACLs on T0 Policies and Silos
    #>

    Write-Host "=" * 80 -ForegroundColor Yellow
    Write-Host "  PHASE 2: Security Object ACL Audit" -ForegroundColor Yellow
    Write-Host "=" * 80 -ForegroundColor Yellow
    Write-Host ""

    $Results = [System.Collections.ArrayList]::new()

    # Audit T0 Policies
    Write-Host "[Phase 2.1] Auditing ACLs on T0 Authentication Policies..." -ForegroundColor Cyan

    foreach ($policy in $Script:T0Policies) {
        Write-Host "    Checking: $($policy.Name)" -ForegroundColor Gray

        try {
            $acl = Get-Acl "AD:\$($policy.DN)"

            foreach ($ace in $acl.Access) {
                if ($ace.IsInherited -and -not $IncludeInherited) {
                    continue
                }

                $identityRef = $ace.IdentityReference.ToString()
                $identitySID = ""
                try {
                    $ntAccount = New-Object System.Security.Principal.NTAccount($identityRef)
                    $identitySID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch { }

                $severityResult = Get-SeverityLevel -Rights $ace.ActiveDirectoryRights.ToString() `
                    -IdentityReference $identityRef `
                    -IdentitySID $identitySID `
                    -AccessControlType $ace.AccessControlType.ToString()

                $null = $Results.Add([PSCustomObject]@{
                    ObjectType = "Authentication Policy"
                    ObjectName = $policy.Name
                    ObjectDN = $policy.DN
                    IdentityReference = $identityRef
                    IdentitySID = $identitySID
                    Rights = $ace.ActiveDirectoryRights.ToString()
                    AccessControlType = $ace.AccessControlType.ToString()
                    IsInherited = $ace.IsInherited
                    Severity = $severityResult.Severity
                    Reason = $severityResult.Reason
                })
            }
        }
        catch {
            Write-Host "      [!] Error reading ACL: $_" -ForegroundColor Red
        }
    }

    # Audit T0 Silos
    Write-Host "[Phase 2.2] Auditing ACLs on T0 Authentication Silos..." -ForegroundColor Cyan

    foreach ($silo in $Script:T0Silos) {
        Write-Host "    Checking: $($silo.Name)" -ForegroundColor Gray

        try {
            $acl = Get-Acl "AD:\$($silo.DN)"

            foreach ($ace in $acl.Access) {
                if ($ace.IsInherited -and -not $IncludeInherited) {
                    continue
                }

                $identityRef = $ace.IdentityReference.ToString()
                $identitySID = ""
                try {
                    $ntAccount = New-Object System.Security.Principal.NTAccount($identityRef)
                    $identitySID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch { }

                $severityResult = Get-SeverityLevel -Rights $ace.ActiveDirectoryRights.ToString() `
                    -IdentityReference $identityRef `
                    -IdentitySID $identitySID `
                    -AccessControlType $ace.AccessControlType.ToString()

                $null = $Results.Add([PSCustomObject]@{
                    ObjectType = "Authentication Silo"
                    ObjectName = $silo.Name
                    ObjectDN = $silo.DN
                    IdentityReference = $identityRef
                    IdentitySID = $identitySID
                    Rights = $ace.ActiveDirectoryRights.ToString()
                    AccessControlType = $ace.AccessControlType.ToString()
                    IsInherited = $ace.IsInherited
                    Severity = $severityResult.Severity
                    Reason = $severityResult.Reason
                })
            }
        }
        catch {
            Write-Host "      [!] Error reading ACL: $_" -ForegroundColor Red
        }
    }

    # Summary
    $criticalCount = ($Results | Where-Object { $_.Severity -eq "Critical" }).Count
    $healthyCount = ($Results | Where-Object { $_.Severity -eq "Healthy" }).Count
    $infoCount = ($Results | Where-Object { $_.Severity -eq "Info" }).Count

    Write-Host ""
    Write-Host "[Phase 2 Complete] ACL Audit Summary:" -ForegroundColor Green
    Write-Host "    Critical (Unauthorized):  $criticalCount" -ForegroundColor $(if ($criticalCount -gt 0) { "Red" } else { "Green" })
    Write-Host "    Healthy (Expected):       $healthyCount" -ForegroundColor Green
    Write-Host "    Informational:            $infoCount" -ForegroundColor Gray
    Write-Host ""

    return $Results
}

#endregion

#region Phase 3: Gap Analysis

function Invoke-Phase3GapAnalysis {
    <#
    .SYNOPSIS
        Phase 3: Gap Analysis - Find unprotected privileged accounts and infrastructure
    #>

    Write-Host "=" * 80 -ForegroundColor Yellow
    Write-Host "  PHASE 3: Gap Analysis (Compliance Check)" -ForegroundColor Yellow
    Write-Host "=" * 80 -ForegroundColor Yellow
    Write-Host ""

    $Results = [System.Collections.ArrayList]::new()

    # Audit A: High-Privilege Account Gap
    Write-Host "[Phase 3.1] Checking High-Privilege Account Protection..." -ForegroundColor Cyan

    foreach ($user in $Script:PrivilegedUsers) {
        $hasPolicy = -not [string]::IsNullOrEmpty($user.AuthNPolicy)
        $hasSilo = -not [string]::IsNullOrEmpty($user.AuthNPolicySilo)
        $isProtected = $hasPolicy -or $hasSilo

        $status = if ($isProtected) { "Protected" } else { "UNPROTECTED" }
        $severity = if (-not $isProtected) {
            if ($user.Criticality -eq "Critical") { "Critical" } else { "High" }
        } else { "Info" }

        $protectionDetails = @()
        if ($hasPolicy) {
            $policyName = ($user.AuthNPolicy -split ",")[0] -replace "CN=", ""
            $protectionDetails += "Policy: $policyName"
        }
        if ($hasSilo) {
            $siloName = ($user.AuthNPolicySilo -split ",")[0] -replace "CN=", ""
            $protectionDetails += "Silo: $siloName"
        }
        if (-not $isProtected) {
            $protectionDetails += "NO POLICY ASSIGNED - Can authenticate from any device!"
        }

        $null = $Results.Add([PSCustomObject]@{
            GapType = "Privileged Account"
            ObjectName = $user.Name
            SamAccountName = $user.SamAccountName
            ObjectDN = $user.DN
            MemberOf = $user.MemberOf
            Enabled = $user.Enabled
            ProtectionStatus = $status
            ProtectionDetails = ($protectionDetails -join "; ")
            Severity = $severity
        })
    }

    $unprotectedUsers = ($Results | Where-Object { $_.GapType -eq "Privileged Account" -and $_.ProtectionStatus -eq "UNPROTECTED" }).Count
    Write-Host "    Privileged users without policy: $unprotectedUsers" -ForegroundColor $(if ($unprotectedUsers -gt 0) { "Red" } else { "Green" })

    # Audit B: Domain Controller Infrastructure Gap
    Write-Host "[Phase 3.2] Checking Domain Controller Infrastructure Protection..." -ForegroundColor Cyan

    # Build list of computers in T0 infrastructure groups
    $t0ComputerDNs = $Script:T0InfrastructureComputers | ForEach-Object { $_.DN }

    foreach ($dc in $Script:DomainControllers) {
        $inT0Group = $t0ComputerDNs -contains $dc.DN
        $hasPolicy = -not [string]::IsNullOrEmpty($dc.AuthNPolicy)
        $hasSilo = -not [string]::IsNullOrEmpty($dc.AuthNPolicySilo)

        $issues = @()
        $severity = "Info"

        if (-not $inT0Group -and $Script:T0InfrastructureGroups.Count -gt 0) {
            $issues += "NOT in T0 Infrastructure Group - T0 Admins cannot sign on!"
            $severity = "Critical"
        }

        if (-not $hasPolicy -and -not $hasSilo) {
            $issues += "No AuthN Policy/Silo assigned directly"
            if ($severity -ne "Critical") { $severity = "Warning" }
        }

        $status = if ($issues.Count -eq 0) { "Compliant" } else { "NON-COMPLIANT" }

        $protectionDetails = @()
        if ($inT0Group) { $protectionDetails += "In T0 Group: Yes" }
        if ($hasPolicy) {
            $policyName = ($dc.AuthNPolicy -split ",")[0] -replace "CN=", ""
            $protectionDetails += "Policy: $policyName"
        }
        if ($hasSilo) {
            $siloName = ($dc.AuthNPolicySilo -split ",")[0] -replace "CN=", ""
            $protectionDetails += "Silo: $siloName"
        }
        if ($issues.Count -gt 0) {
            $protectionDetails += "ISSUES: " + ($issues -join "; ")
        }

        $null = $Results.Add([PSCustomObject]@{
            GapType = "Domain Controller"
            ObjectName = $dc.Name
            SamAccountName = $dc.Name + "$"
            ObjectDN = $dc.DN
            MemberOf = "Domain Controllers ($($dc.Type))"
            Enabled = $true
            ProtectionStatus = $status
            ProtectionDetails = ($protectionDetails -join "; ")
            Severity = $severity
        })
    }

    $nonCompliantDCs = ($Results | Where-Object { $_.GapType -eq "Domain Controller" -and $_.ProtectionStatus -eq "NON-COMPLIANT" }).Count
    Write-Host "    Non-compliant Domain Controllers: $nonCompliantDCs" -ForegroundColor $(if ($nonCompliantDCs -gt 0) { "Red" } else { "Green" })

    # Audit C: Policy-to-Silo Mapping Check
    Write-Host "[Phase 3.3] Checking Policy-to-Silo Enforcement..." -ForegroundColor Cyan

    foreach ($policy in $Script:T0Policies) {
        # Check if this policy is bound to a silo
        $boundToSilo = $false
        $boundSiloName = ""

        foreach ($silo in $Script:T0Silos) {
            if ($silo.UserPolicy -eq $policy.DN -or
                $silo.ComputerPolicy -eq $policy.DN -or
                $silo.ServicePolicy -eq $policy.DN) {
                $boundToSilo = $true
                $boundSiloName = $silo.Name
                break
            }
        }

        if (-not $boundToSilo) {
            $null = $Results.Add([PSCustomObject]@{
                GapType = "Policy Configuration"
                ObjectName = $policy.Name
                SamAccountName = "N/A"
                ObjectDN = $policy.DN
                MemberOf = "Authentication Policy"
                Enabled = $true
                ProtectionStatus = "WARNING"
                ProtectionDetails = "Policy not bound to any Silo - May not enforce strict authentication!"
                Severity = "Warning"
            })
        }
    }

    $unboundPolicies = ($Results | Where-Object { $_.GapType -eq "Policy Configuration" }).Count
    Write-Host "    Policies not bound to Silos: $unboundPolicies" -ForegroundColor $(if ($unboundPolicies -gt 0) { "Yellow" } else { "Green" })

    Write-Host ""
    Write-Host "[Phase 3 Complete] Gap Analysis Summary:" -ForegroundColor Green
    $criticalGaps = ($Results | Where-Object { $_.Severity -eq "Critical" }).Count
    $warningGaps = ($Results | Where-Object { $_.Severity -eq "Warning" }).Count
    Write-Host "    Critical Gaps: $criticalGaps" -ForegroundColor $(if ($criticalGaps -gt 0) { "Red" } else { "Green" })
    Write-Host "    Warnings:      $warningGaps" -ForegroundColor $(if ($warningGaps -gt 0) { "Yellow" } else { "Green" })
    Write-Host ""

    return $Results
}

#endregion

#region Phase 4: Access Map (Reachability Report)

function Invoke-Phase4AccessMap {
    <#
    .SYNOPSIS
        Phase 4: Map where T0 admins can authenticate
    #>

    Write-Host "=" * 80 -ForegroundColor Yellow
    Write-Host "  PHASE 4: Access Map (Reachability Report)" -ForegroundColor Yellow
    Write-Host "=" * 80 -ForegroundColor Yellow
    Write-Host ""

    $Results = [System.Collections.ArrayList]::new()

    Write-Host "[Phase 4.1] Mapping T0 Admin Effective Perimeter..." -ForegroundColor Cyan

    foreach ($computer in $Script:T0InfrastructureComputers) {
        $status = if ($computer.IsDomainController) { "Expected" } else { "WARNING - T0 Pollution" }
        $severity = if ($computer.IsDomainController) { "Info" } else { "Warning" }

        $null = $Results.Add([PSCustomObject]@{
            ComputerName = $computer.Name
            DNSHostName = $computer.DNSHostName
            OperatingSystem = $computer.OperatingSystem
            IsDomainController = $computer.IsDomainController
            SourceGroup = $computer.SourceGroup
            Status = $status
            Severity = $severity
            DN = $computer.DN
        })
    }

    # Check for DCs not in any T0 group
    foreach ($dc in $Script:DomainControllers) {
        $inResults = $Results | Where-Object { $_.DN -eq $dc.DN }
        if (-not $inResults) {
            $null = $Results.Add([PSCustomObject]@{
                ComputerName = $dc.Name
                DNSHostName = $dc.DNSHostName
                OperatingSystem = $dc.OperatingSystem
                IsDomainController = $true
                SourceGroup = "NONE - Not in any T0 Group!"
                Status = "CRITICAL - DC Unreachable by T0 Admins"
                Severity = "Critical"
                DN = $dc.DN
            })
        }
    }

    # Summary
    $dcCount = ($Results | Where-Object { $_.IsDomainController }).Count
    $nonDCCount = ($Results | Where-Object { -not $_.IsDomainController }).Count
    $criticalCount = ($Results | Where-Object { $_.Severity -eq "Critical" }).Count

    Write-Host ""
    Write-Host "[Phase 4 Complete] Access Map Summary:" -ForegroundColor Green
    Write-Host "    Domain Controllers in Perimeter: $dcCount" -ForegroundColor White
    Write-Host "    Non-DC Servers (T0 Pollution):   $nonDCCount" -ForegroundColor $(if ($nonDCCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "    Critical (DCs not reachable):    $criticalCount" -ForegroundColor $(if ($criticalCount -gt 0) { "Red" } else { "Green" })
    Write-Host ""

    return $Results
}

#endregion

#region Phase 5: Report Generation

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Phase 5: Generate comprehensive HTML report with 3 tables
    #>
    param(
        [System.Collections.ArrayList]$ACLResults,
        [System.Collections.ArrayList]$GapResults,
        [System.Collections.ArrayList]$AccessMapResults
    )

    Write-Host "=" * 80 -ForegroundColor Yellow
    Write-Host "  PHASE 5: Report Generation" -ForegroundColor Yellow
    Write-Host "=" * 80 -ForegroundColor Yellow
    Write-Host ""

    $FilePath = Join-Path $OutputPath "T0_Security_Audit_Report.html"
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Count findings
    $ACLCritical = ($ACLResults | Where-Object { $_.Severity -eq "Critical" }).Count
    $GapCritical = ($GapResults | Where-Object { $_.Severity -eq "Critical" }).Count
    $GapWarning = ($GapResults | Where-Object { $_.Severity -eq "Warning" }).Count
    $AccessWarning = ($AccessMapResults | Where-Object { $_.Severity -eq "Warning" }).Count
    $AccessCritical = ($AccessMapResults | Where-Object { $_.Severity -eq "Critical" }).Count

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
            --warning-color: #fd7e14;
            --warning-bg: #fff3cd;
            --healthy-color: #28a745;
            --healthy-bg: #d4edda;
            --info-color: #17a2b8;
            --info-bg: #d1ecf1;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; color: #333; padding: 20px; }
        .container { max-width: 1600px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { font-size: 1.8em; margin-bottom: 5px; }
        .header .subtitle { opacity: 0.8; }
        .header .timestamp { margin-top: 15px; font-size: 0.9em; opacity: 0.7; }

        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .summary-card { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-card .count { font-size: 2.5em; font-weight: bold; }
        .summary-card .label { color: #666; font-size: 0.9em; }
        .summary-card.critical .count { color: var(--critical-color); }
        .summary-card.warning .count { color: var(--warning-color); }
        .summary-card.healthy .count { color: var(--healthy-color); }

        .section { background: white; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }
        .section-header { background: #f8f9fa; padding: 15px 20px; border-bottom: 1px solid #dee2e6; display: flex; justify-content: space-between; align-items: center; }
        .section-header h2 { font-size: 1.2em; color: #1a1a2e; }
        .section-header .badge { padding: 5px 12px; border-radius: 20px; font-size: 0.85em; color: white; }
        .section-header .badge.critical { background: var(--critical-color); }
        .section-header .badge.warning { background: var(--warning-color); }
        .section-header .badge.healthy { background: var(--healthy-color); }

        .table-container { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
        th { background: #1a1a2e; color: white; padding: 12px 15px; text-align: left; font-weight: 600; }
        td { padding: 10px 15px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f8f9fa; }

        .severity-badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 0.85em; }
        .severity-critical { background: var(--critical-bg); color: var(--critical-color); }
        .severity-warning { background: var(--warning-bg); color: #856404; }
        .severity-healthy { background: var(--healthy-bg); color: var(--healthy-color); }
        .severity-info { background: var(--info-bg); color: var(--info-color); }

        .row-critical { background: var(--critical-bg) !important; }
        .row-warning { background: var(--warning-bg) !important; }

        .discovery-summary { background: #e7f3ff; border-left: 4px solid #0066cc; padding: 15px 20px; margin-bottom: 20px; border-radius: 0 10px 10px 0; }
        .discovery-summary h3 { color: #0066cc; margin-bottom: 10px; }
        .discovery-summary ul { list-style: none; }
        .discovery-summary li { padding: 5px 0; }
        .discovery-summary li::before { content: "[OK] "; color: #28a745; font-weight: bold; }

        .note { background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px 15px; margin: 15px 0; border-radius: 0 5px 5px 0; font-size: 0.9em; }
        .note.info { background: var(--info-bg); border-color: var(--info-color); }

        .no-findings { padding: 40px; text-align: center; color: #28a745; }
        .no-findings .icon { font-size: 3em; margin-bottom: 10px; }

        @media print { body { background: white; } .section { break-inside: avoid; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>T0 Authentication Security Infrastructure Audit</h1>
            <div class="subtitle">Dynamic Discovery Mode - No Static Filters</div>
            <div class="timestamp">Generated: $Timestamp | Domain: $($Script:DomainInfo.DNSRoot)</div>
        </div>

        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="count">$($ACLCritical + $GapCritical + $AccessCritical)</div>
                <div class="label">Critical Findings</div>
            </div>
            <div class="summary-card warning">
                <div class="count">$($GapWarning + $AccessWarning)</div>
                <div class="label">Warnings</div>
            </div>
            <div class="summary-card healthy">
                <div class="count">$($Script:PrivilegedUsers.Count)</div>
                <div class="label">Privileged Users Analyzed</div>
            </div>
            <div class="summary-card">
                <div class="count">$($Script:DomainControllers.Count)</div>
                <div class="label">Domain Controllers</div>
            </div>
        </div>

        <div class="discovery-summary">
            <h3>Phase 1 Discovery Results</h3>
            <ul>
                <li>$($Script:DomainControllers.Count) Domain Controllers identified</li>
                <li>$($Script:PrivilegedUsers.Count) Privileged Users (DA/EA/SA members)</li>
                <li>$($Script:T0Policies.Count) T0 Authentication Policies discovered</li>
                <li>$($Script:T0Silos.Count) T0 Authentication Silos discovered</li>
                <li>$($Script:T0InfrastructureGroups.Count) T0 Infrastructure Groups mapped</li>
                <li>$($Script:T0InfrastructureComputers.Count) Computers in T0 perimeter</li>
            </ul>
        </div>

        <!-- TABLE 1: ACL Trust Report - Full Details -->
        <div class="section">
            <div class="section-header">
                <h2>1. ACL Trust Report - All Permissions on T0 Security Objects</h2>
                <span class="badge $(if ($ACLCritical -gt 0) { 'critical' } else { 'healthy' })">$($ACLResults.Count) Total, $ACLCritical Critical</span>
            </div>
            <div class="table-container">
"@

    # Show ALL ACLs grouped by object, with color coding
    if ($ACLResults.Count -gt 0) {
        # Group by object for better readability
        $groupedACLs = $ACLResults | Group-Object -Property ObjectName

        foreach ($objectGroup in $groupedACLs) {
            $objectName = $objectGroup.Name
            $objectType = $objectGroup.Group[0].ObjectType
            $objectCriticalCount = ($objectGroup.Group | Where-Object { $_.Severity -eq "Critical" }).Count

            $objectHeaderClass = if ($objectCriticalCount -gt 0) { "background: #f8d7da;" } else { "background: #e7f3ff;" }

            $HTML += @"
                <div style="margin: 15px 0; border: 1px solid #dee2e6; border-radius: 8px; overflow: hidden;">
                    <div style="$objectHeaderClass padding: 10px 15px; font-weight: bold; border-bottom: 1px solid #dee2e6;">
                        ${objectType}: ${objectName}
                        $(if ($objectCriticalCount -gt 0) { "<span class='severity-badge severity-critical' style='margin-left: 10px;'>$objectCriticalCount CRITICAL</span>" })
                    </div>
                    <table style="margin: 0;">
                        <thead>
                            <tr>
                                <th style="width: 100px;">Severity</th>
                                <th>Identity</th>
                                <th>Rights</th>
                                <th>Type</th>
                                <th>Inherited</th>
                                <th>Classification</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            # Sort by severity (Critical first, then others)
            $sortedACLs = $objectGroup.Group | Sort-Object @{Expression={
                switch ($_.Severity) { "Critical" { 0 } "Medium" { 1 } "Healthy" { 2 } "Info" { 3 } default { 4 } }
            }}

            foreach ($acl in $sortedACLs) {
                $rowClass = switch ($acl.Severity) {
                    "Critical" { "row-critical" }
                    "Medium" { "row-warning" }
                    default { "" }
                }
                $severityClass = switch ($acl.Severity) {
                    "Critical" { "severity-critical" }
                    "Medium" { "severity-warning" }
                    "Healthy" { "severity-healthy" }
                    "Info" { "severity-info" }
                    default { "severity-info" }
                }
                $severityText = $acl.Severity.ToUpper()

                $HTML += @"
                            <tr class="$rowClass">
                                <td><span class="severity-badge $severityClass">$severityText</span></td>
                                <td>$($acl.IdentityReference)</td>
                                <td><code style="font-size: 0.85em;">$($acl.Rights)</code></td>
                                <td>$($acl.AccessControlType)</td>
                                <td>$(if ($acl.IsInherited) { 'Yes' } else { 'No' })</td>
                                <td>$($acl.Reason)</td>
                            </tr>
"@
            }

            $HTML += @"
                        </tbody>
                    </table>
                </div>
"@
        }
    }
    else {
        $HTML += '<div class="no-findings"><div class="icon">!</div>No T0 Authentication Policies or Silos were discovered. ACL audit could not be performed.</div>'
    }

    $HTML += @"
            </div>
            <div class="note info">
                <strong>Severity Legend:</strong><br>
                <span class="severity-badge severity-critical">CRITICAL</span> Unauthorized identity with modify rights - privilege escalation path<br>
                <span class="severity-badge severity-warning">MEDIUM</span> Non-standard permission - review recommended<br>
                <span class="severity-badge severity-healthy">HEALTHY</span> Expected permission (Domain Admins, Enterprise Admins)<br>
                <span class="severity-badge severity-info">INFO</span> System/read-only permission - required for AD operations
            </div>
        </div>

        <!-- TABLE 2: Identity & Infrastructure Gaps -->
        <div class="section">
            <div class="section-header">
                <h2>2. Identity & Infrastructure Gaps</h2>
                <span class="badge $(if ($GapCritical -gt 0) { 'critical' } elseif ($GapWarning -gt 0) { 'warning' } else { 'healthy' })">$GapCritical Critical, $GapWarning Warnings</span>
            </div>
            <div class="table-container">
"@

    $gapFindings = $GapResults | Where-Object { $_.Severity -ne "Info" }

    if ($gapFindings.Count -gt 0) {
        $HTML += @"
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Gap Type</th>
                            <th>Object</th>
                            <th>Member Of</th>
                            <th>Status</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($gap in ($gapFindings | Sort-Object @{Expression={switch($_.Severity){"Critical"{0}"Warning"{1}default{2}}}})) {
            $rowClass = switch ($gap.Severity) { "Critical" { "row-critical" } "Warning" { "row-warning" } default { "" } }
            $severityClass = "severity-$($gap.Severity.ToLower())"

            $HTML += @"
                        <tr class="$rowClass">
                            <td><span class="severity-badge $severityClass">$($gap.Severity.ToUpper())</span></td>
                            <td>$($gap.GapType)</td>
                            <td><strong>$($gap.ObjectName)</strong></td>
                            <td>$($gap.MemberOf)</td>
                            <td>$($gap.ProtectionStatus)</td>
                            <td>$($gap.ProtectionDetails)</td>
                        </tr>
"@
        }
        $HTML += "</tbody></table>"
    }
    else {
        $HTML += '<div class="no-findings"><div class="icon">[OK]</div>All privileged accounts and Domain Controllers are properly protected!</div>'
    }

    # Show protected accounts count
    $protectedCount = ($GapResults | Where-Object { $_.Severity -eq "Info" }).Count
    $HTML += @"
            </div>
            <div class="note info">
                <strong>Protected:</strong> $protectedCount privileged accounts/DCs are properly assigned to Authentication Policies or Silos.
            </div>
        </div>

        <!-- TABLE 3: Effective Perimeter Map -->
        <div class="section">
            <div class="section-header">
                <h2>3. Effective Perimeter Map - T0 Admin Reachability</h2>
                <span class="badge $(if ($AccessCritical -gt 0) { 'critical' } elseif ($AccessWarning -gt 0) { 'warning' } else { 'healthy' })">$($AccessMapResults.Count) Computers</span>
            </div>
            <div class="table-container">
"@

    if ($AccessMapResults.Count -gt 0) {
        $HTML += @"
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Computer</th>
                            <th>DNS Name</th>
                            <th>Operating System</th>
                            <th>Is DC?</th>
                            <th>Source Group</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($comp in ($AccessMapResults | Sort-Object @{Expression={switch($_.Severity){"Critical"{0}"Warning"{1}default{2}}}}, IsDomainController -Descending)) {
            $rowClass = switch ($comp.Severity) { "Critical" { "row-critical" } "Warning" { "row-warning" } default { "" } }
            $severityClass = switch ($comp.Severity) { "Critical" { "severity-critical" } "Warning" { "severity-warning" } default { "severity-healthy" } }
            $statusText = switch ($comp.Severity) { "Critical" { "CRITICAL" } "Warning" { "WARNING" } default { "OK" } }

            $HTML += @"
                        <tr class="$rowClass">
                            <td><span class="severity-badge $severityClass">$statusText</span></td>
                            <td><strong>$($comp.ComputerName)</strong></td>
                            <td>$($comp.DNSHostName)</td>
                            <td>$($comp.OperatingSystem)</td>
                            <td>$(if ($comp.IsDomainController) { 'Yes' } else { 'No' })</td>
                            <td>$($comp.SourceGroup)</td>
                        </tr>
"@
        }
        $HTML += "</tbody></table>"
    }
    else {
        $HTML += '<div class="no-findings"><div class="icon">[!]</div>No T0 Infrastructure Groups found. Unable to map T0 admin reachability.</div>'
    }

    $HTML += @"
            </div>
            <div class="note">
                <strong>T0 Pollution Warning:</strong> Non-DC servers in T0 infrastructure groups allow T0 admins to sign on, potentially exposing credentials. Review if these servers truly require T0 access.
            </div>
        </div>
    </div>
</body>
</html>
"@

    $HTML | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "[+] HTML Report: $FilePath" -ForegroundColor Green

    return $FilePath
}

function Export-CSVReports {
    <#
    .SYNOPSIS
        Export CSV reports for each phase
    #>
    param(
        [System.Collections.ArrayList]$ACLResults,
        [System.Collections.ArrayList]$GapResults,
        [System.Collections.ArrayList]$AccessMapResults
    )

    # ACL Report
    $aclPath = Join-Path $OutputPath "T0_ACL_Trust_Report.csv"
    $ACLResults | Export-Csv -Path $aclPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] ACL Report: $aclPath" -ForegroundColor Green

    # Gap Report
    $gapPath = Join-Path $OutputPath "T0_Gap_Analysis.csv"
    $GapResults | Export-Csv -Path $gapPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Gap Analysis: $gapPath" -ForegroundColor Green

    # Access Map
    $accessPath = Join-Path $OutputPath "T0_Access_Map.csv"
    $AccessMapResults | Export-Csv -Path $accessPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Access Map: $accessPath" -ForegroundColor Green

    # Discovery Summary
    $discoveryPath = Join-Path $OutputPath "T0_Discovery_Summary.csv"
    $discovery = @(
        [PSCustomObject]@{ Category = "Domain Controllers"; Count = $Script:DomainControllers.Count; Details = ($Script:DomainControllers.Name -join ", ") }
        [PSCustomObject]@{ Category = "Privileged Users"; Count = $Script:PrivilegedUsers.Count; Details = ($Script:PrivilegedUsers.Name -join ", ") }
        [PSCustomObject]@{ Category = "T0 Policies"; Count = $Script:T0Policies.Count; Details = ($Script:T0Policies.Name -join ", ") }
        [PSCustomObject]@{ Category = "T0 Silos"; Count = $Script:T0Silos.Count; Details = ($Script:T0Silos.Name -join ", ") }
        [PSCustomObject]@{ Category = "T0 Infrastructure Groups"; Count = $Script:T0InfrastructureGroups.Count; Details = ($Script:T0InfrastructureGroups.Name -join ", ") }
        [PSCustomObject]@{ Category = "T0 Infrastructure Computers"; Count = $Script:T0InfrastructureComputers.Count; Details = ($Script:T0InfrastructureComputers.Name -join ", ") }
    )
    $discovery | Export-Csv -Path $discoveryPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Discovery Summary: $discoveryPath" -ForegroundColor Green
}

#endregion

#region Main Execution

try {
    # Initialize
    Initialize-AuditEnvironment

    # Phase 1: Discovery
    Invoke-Phase1Discovery

    # Check if we found any T0 policies
    if ($Script:T0Policies.Count -eq 0 -and $Script:T0Silos.Count -eq 0) {
        Write-Host ""
        Write-Host "[!] WARNING: No T0 Authentication Policies or Silos were discovered!" -ForegroundColor Red
        Write-Host "    This means either:" -ForegroundColor Yellow
        Write-Host "    1. No privileged users have Authentication Policies assigned" -ForegroundColor Yellow
        Write-Host "    2. Authentication Policies are not configured in this environment" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    The audit will continue but Gap Analysis will show all privileged accounts as UNPROTECTED." -ForegroundColor Yellow
        Write-Host ""
    }

    # Phase 2: ACL Audit
    $ACLResults = Invoke-Phase2ACLAudit

    # Phase 3: Gap Analysis
    $GapResults = Invoke-Phase3GapAnalysis

    # Phase 4: Access Map
    $AccessMapResults = Invoke-Phase4AccessMap

    # Phase 5: Reports
    Write-Host "[Phase 5.1] Exporting CSV Reports..." -ForegroundColor Cyan
    Export-CSVReports -ACLResults $ACLResults -GapResults $GapResults -AccessMapResults $AccessMapResults

    Write-Host "[Phase 5.2] Generating HTML Report..." -ForegroundColor Cyan
    $htmlPath = Export-HTMLReport -ACLResults $ACLResults -GapResults $GapResults -AccessMapResults $AccessMapResults

    # Final Summary
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host "  AUDIT COMPLETE" -ForegroundColor Green
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host ""
    Write-Host "  Reports saved to: $OutputPath" -ForegroundColor White
    Write-Host ""

    $totalCritical = ($ACLResults | Where-Object { $_.Severity -eq "Critical" }).Count +
                     ($GapResults | Where-Object { $_.Severity -eq "Critical" }).Count +
                     ($AccessMapResults | Where-Object { $_.Severity -eq "Critical" }).Count

    if ($totalCritical -gt 0) {
        Write-Host "  [!] $totalCritical CRITICAL FINDINGS REQUIRE IMMEDIATE ATTENTION" -ForegroundColor Red
    }
    else {
        Write-Host "  [OK] No critical findings. T0 security posture appears healthy." -ForegroundColor Green
    }
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}

#endregion
