<#
.SYNOPSIS
    Generates synthetic Evaluate-STIG-style .cklb sample checklists for the
    dashboard's "sample checklists" folder.

.DESCRIPTION
    Builds fake but structurally valid CKLB (JSON) checklists for a library of
    common DoD device types (domain controllers, SQL/PostgreSQL servers,
    switches, routers, firewalls, ESXi/vCenter, workstations, mail servers,
    dev-shop services, mobile/endpoint devices, etc.) so the dashboard has a
    realistic, varied dataset to demo against without needing real scan data.

    Each device "profile" (STIG title + a handful of rule topics/severities)
    is defined once and reused across multiple hosts; per-host finding
    statuses (Open / NotAFinding / Not_Reviewed / Not_Applicable) are assigned
    from a weighted pool seeded by hostname+STIG so results are varied but
    reproducible-looking rather than identical copies of each other.

.NOTES
    Re-running this script overwrites any existing files of the same name in
    the output folder. To add more sample assets, either add a New-Asset call
    at the bottom using existing profiles, or define a new profile (same
    shape as the existing ones) and reference it in a New-Asset call.

.EXAMPLE
    pwsh ./tools/generate-sample-checklists.ps1
#>

$ErrorActionPreference = "Stop"
$outDir = Join-Path $PSScriptRoot "..\sample checklists"
$scanDate = (Get-Date).ToString("MM/dd/yyyy")
$scanTimeBase = Get-Date

# ===========================================================================
# Low-level helpers
# ===========================================================================

function New-Hash {
    -join ((1..40) | ForEach-Object { "{0:X}" -f (Get-Random -Maximum 16) })
}

function New-Rule {
    param(
        [string]$GroupId, [string]$RuleTitle, [string]$RuleIdNum, [string]$RuleVersion,
        [string]$Severity, [string]$Status, [string]$TechName, [string]$ModuleName, [string]$ModuleVersion
    )
    $ruleId = "SV-$RuleIdNum"
    $findingDetails = ""
    $comments = ""
    switch ($Status) {
        "open" {
            $findingDetails = "Evaluate-STIG $ModuleVersion ($ModuleName) found this to be OPEN on $scanDate`r`nResultHash: $(New-Hash)`r`n~~~~~`r`nRequired configuration for '$RuleTitle' was not present or did not match the expected value on $TechName."
        }
        "notafinding" {
            $findingDetails = "Evaluate-STIG $ModuleVersion ($ModuleName) found this to be NotAFinding on $scanDate`r`nResultHash: $(New-Hash)`r`n~~~~~`r`nConfiguration for '$RuleTitle' matches the expected value on $TechName."
        }
        "not_applicable" {
            $findingDetails = "Evaluate-STIG $ModuleVersion ($ModuleName) marked this Not_Applicable on $scanDate`r`nResultHash: $(New-Hash)`r`n~~~~~`r`nThe feature/role addressed by '$RuleTitle' is not present or not in use on this $TechName."
            $comments = "Not applicable - capability not installed/enabled on this asset."
        }
        default {
            $findingDetails = ""
        }
    }
    [ordered]@{
        group_id_src               = $GroupId
        group_tree                 = @(@{ id = $GroupId; title = "SRG-$($TechName -replace '[^A-Za-z0-9]','')"; description = "<GroupDescription></GroupDescription>" })
        group_id                   = $GroupId
        severity                   = $Severity
        group_title                = $RuleTitle
        rule_id_src                = "$ruleId`_rule"
        rule_id                    = $ruleId
        rule_version               = $RuleVersion
        rule_title                 = $RuleTitle
        fix_text                   = "Configure $TechName in accordance with site policy so that the requirement is met: $RuleTitle"
        weight                     = "10.0"
        check_content              = "Review the $TechName configuration relevant to this requirement. If the configuration does not satisfy '$RuleTitle', this is a finding."
        check_content_ref          = [ordered]@{ href = "$($TechName -replace '[^A-Za-z0-9]','_')_STIG.xml"; name = "M" }
        classification              = "UNCLASSIFIED"
        discussion                 = "Failure to meet this requirement increases risk to the confidentiality, integrity, or availability of $TechName and the data it processes. This control addresses: $RuleTitle"
        false_positives             = ""
        false_negatives             = ""
        documentable                = "false"
        security_override_guidance  = ""
        potential_impacts           = ""
        third_party_tools           = ""
        ia_controls                 = ""
        responsibility               = ""
        mitigations                  = ""
        mitigation_control           = ""
        legacy_ids                  = @()
        ccis                        = @("CCI-000$(Get-Random -Minimum 100 -Maximum 999)")
        reference_identifier        = "$(Get-Random -Minimum 1000 -Maximum 9999)"
        uuid                        = [guid]::NewGuid().ToString()
        stig_uuid                   = $script:currentStigUuid
        status                      = $Status
        overrides                   = [ordered]@{}
        comments                    = $comments
        finding_details             = $findingDetails
    }
}

function New-Stig {
    param(
        [string]$DisplayName, [string]$StigId, [string]$StigName, [string]$ReleaseInfo,
        [string]$Version, [string]$ModuleName, [string]$ModuleVersion, [array]$RuleDefs, [string]$TechName
    )
    $script:currentStigUuid = [guid]::NewGuid().ToString()
    $rules = @()
    foreach ($rd in $RuleDefs) {
        $rules += New-Rule -GroupId $rd.GroupId -RuleTitle $rd.Title -RuleIdNum $rd.RuleIdNum -RuleVersion $rd.RuleVersion `
            -Severity $rd.Severity -Status $rd.Status -TechName $TechName -ModuleName $ModuleName -ModuleVersion $ModuleVersion
    }
    [ordered]@{
        "evaluate-stig"       = [ordered]@{
            time   = $scanTimeBase.ToString("yyyy-MM-ddTHH:mm:ss.fffffffzzz")
            module = [ordered]@{ name = $ModuleName; version = $ModuleVersion }
        }
        stig_name             = $StigName
        display_name          = $DisplayName
        stig_id               = $StigId
        release_info          = $ReleaseInfo
        version               = $Version
        uuid                  = $script:currentStigUuid
        reference_identifier  = "$(Get-Random -Minimum 1000 -Maximum 9999)"
        size                  = $rules.Count
        rules                 = $rules
    }
}

function New-CklbFile {
    param(
        [string]$FileName, [string]$HostName, [string]$IpAddress, [string]$MacAddress, [string]$Fqdn,
        [string]$Role, [string]$TechArea = "None", [bool]$IsWebDb = $false, [array]$Stigs
    )
    $obj = [ordered]@{
        active         = $false
        cklb_version   = "1.0"
        "evaluate-stig" = [ordered]@{ version = "1.2604.2" }
        has_path       = $true
        id             = [guid]::NewGuid().ToString()
        mode           = 1
        stigs          = $Stigs
        target_data    = [ordered]@{
            target_type     = "Computing"
            host_name       = $HostName
            ip_address      = $IpAddress
            mac_address     = $MacAddress
            fqdn            = $Fqdn
            comments        = ""
            role            = $Role
            is_web_database = $IsWebDb
            technology_area = $TechArea
            web_db_site     = ""
            web_db_instance = ""
            classification  = ""
        }
        title          = "Evaluate-STIG_COMBINED"
    }
    $json = $obj | ConvertTo-Json -Depth 12 -Compress
    $path = Join-Path $outDir $FileName
    [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Output "Wrote $path ($($json.Length) bytes)"
}

# ===========================================================================
# Batch-2-only helpers: topic -> rule-id generation, seeded status pools,
# and simple IP/MAC allocators so 58 hosts don't need to be hand-addressed.
# ===========================================================================

$script:ruleNumCounter = 300000
function Next-RuleNum { $script:ruleNumCounter += (Get-Random -Minimum 3 -Maximum 9); return $script:ruleNumCounter }

function New-TopicList {
    param([string]$Code, [array]$Items)  # Items: array of @(Title, Severity)
    $list = @()
    foreach ($it in $Items) {
        $n = Next-RuleNum
        $list += [ordered]@{
            GroupId     = "V-$n"
            RuleIdNum   = "$($n)r$(Next-RuleNum)"
            RuleVersion = "$Code-$('{0:D6}' -f $n)"
            Title       = $it[0]
            Severity    = $it[1]
        }
    }
    return $list
}

function Get-StableHash([string]$s) {
    $h = 0
    foreach ($c in $s.ToCharArray()) { $h = ($h * 31 + [int][char]$c) -band 0x7FFFFFFF }
    return $h
}

# Weighted status pool: ~29% open, ~43% notafinding, ~14% not_reviewed, ~14% not_applicable
$script:statusPool = @("open","open","notafinding","notafinding","notafinding","not_reviewed","not_applicable")

function New-StigForHost {
    param([hashtable]$Profile, [string]$SeedKey)
    $rnd = New-Object System.Random((Get-StableHash $SeedKey))
    $ruleDefs = @()
    foreach ($t in $Profile.Topics) {
        $status = $script:statusPool[$rnd.Next(0, $script:statusPool.Count)]
        $ruleDefs += @{ GroupId = $t.GroupId; RuleIdNum = $t.RuleIdNum; RuleVersion = $t.RuleVersion; Title = $t.Title; Severity = $t.Severity; Status = $status }
    }
    return New-Stig -DisplayName $Profile.DisplayName -StigId $Profile.StigId -StigName $Profile.StigName `
        -ReleaseInfo $Profile.ReleaseInfo -Version $Profile.Version -ModuleName $Profile.ModuleName `
        -ModuleVersion "1.2026.5.14" -TechName $Profile.TechName -RuleDefs $ruleDefs
}

function New-Asset {
    param([string]$FileName, [string]$HostName, [string]$IpAddress, [string]$MacAddress, [string]$Fqdn,
          [string]$Role, [string]$TechArea = "None", [bool]$IsWebDb = $false, [array]$ProfileList)
    $stigs = @()
    foreach ($p in $ProfileList) { $stigs += New-StigForHost -Profile $p -SeedKey "$HostName|$($p.StigId)" }
    New-CklbFile -FileName $FileName -HostName $HostName -IpAddress $IpAddress -MacAddress $MacAddress -Fqdn $Fqdn `
        -Role $Role -TechArea $TechArea -IsWebDb $IsWebDb -Stigs $stigs
}

$script:ipCounters = @{}
function Next-Ip([string]$prefix, [int]$start = 10) {
    if (-not $script:ipCounters.ContainsKey($prefix)) { $script:ipCounters[$prefix] = $start }
    else { $script:ipCounters[$prefix]++ }
    return "$prefix.$($script:ipCounters[$prefix])"
}
$script:macCounter = 0
function Next-Mac([string]$oui = "00:1C:42") {
    $script:macCounter++
    $b4 = "{0:X2}" -f (($script:macCounter -shr 16) -band 0xFF)
    $b5 = "{0:X2}" -f (($script:macCounter -shr 8) -band 0xFF)
    $b6 = "{0:X2}" -f ($script:macCounter -band 0xFF)
    return "$oui`:$b4`:$b5`:$b6"
}

# ===========================================================================
# STIG profiles (title/topics defined once, reused across many hosts)
# ===========================================================================

$winserver2022 = @{
    DisplayName = "Windows Server 2022"; StigId = "Windows_Server_2022_STIG"
    StigName = "Windows Server 2022 Security Technical Implementation Guide"
    ReleaseInfo = "Release: 4 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-WindowsServer2022_Checks"
    TechName = "the Windows Server 2022 host"
    Topics = New-TopicList -Code "WN22" -Items @(
        @("Windows Server 2022 must have the built-in guest account disabled.","medium"),
        @("Windows Server 2022 minimum password length must be configured to 14 characters.","medium"),
        @("Windows Server 2022 must have WDigest Authentication disabled.","high"),
        @("Windows Server 2022 must prevent local users from being enumerated by an unauthenticated logon.","medium"),
        @("Windows Server 2022 must require encryption for all Remote Desktop Services sessions.","medium"),
        @("Windows Server 2022 must have the Windows Installer Always install with elevated privileges option disabled.","high")
    )
}

$winserver2019 = @{
    DisplayName = "Windows Server 2019"; StigId = "Windows_Server_2019_STIG"
    StigName = "Windows Server 2019 Security Technical Implementation Guide"
    ReleaseInfo = "Release: 6 Benchmark Date: 26 Feb 2026"; Version = "3"; ModuleName = "Scan-WindowsServer2019_Checks"
    TechName = "the Windows Server 2019 host"
    Topics = New-TopicList -Code "WN19" -Items @(
        @("Windows Server 2019 must have the built-in guest account disabled.","medium"),
        @("Windows Server 2019 minimum password length must be configured to 14 characters.","medium"),
        @("Windows Server 2019 must have WDigest Authentication disabled.","high"),
        @("Windows Server 2019 must be configured to audit Logon/Logoff - Logon successes.","low"),
        @("Windows Server 2019 must require encryption for all Remote Desktop Services sessions.","medium"),
        @("Windows Server 2019 must have Autoplay disabled for all drives.","low")
    )
}

$addsstig = @{
    DisplayName = "Active Directory Domain Services"; StigId = "Active_Directory_Domain_Services_STIG"
    StigName = "Active Directory Domain Services Security Technical Implementation Guide"
    ReleaseInfo = "Release: 4 Benchmark Date: 24 Jan 2026"; Version = "3"; ModuleName = "Scan-ADDomainServices_Checks"
    TechName = "Active Directory Domain Services"
    Topics = New-TopicList -Code "AD" -Items @(
        @("Domain Controller PKI certificates must be issued by the DoD PKI or an approved External Certificate Authority.","medium"),
        @("Domain controllers must require LDAP access signing.","high"),
        @("Active Directory Group Policy objects must have proper access control permissions.","medium"),
        @("Membership to the Schema Admins group must be restricted to accounts used only when changes to the schema are planned.","medium"),
        @("The time service must synchronize with an authoritative DoD time source.","medium"),
        @("Domain controllers must have a PKI server certificate installed.","medium")
    )
}

$mssql2016instance = @{
    DisplayName = "MS SQL Server 2016 Instance"; StigId = "MS_SQL_Server_2016_Instance_STIG"
    StigName = "MS SQL Server 2016 Instance Security Technical Implementation Guide"
    ReleaseInfo = "Release: 4 Benchmark Date: 24 Jan 2026"; Version = "2"; ModuleName = "Scan-MSSQLServer2016Instance_Checks"
    TechName = "the SQL Server instance"
    Topics = New-TopicList -Code "SQL6I" -Items @(
        @("SQL Server must limit the use of the SA account.","medium"),
        @("SQL Server must encrypt sensitive data in storage.","high"),
        @("SQL Server must enforce access restrictions associated with changes to the configuration of the SQL Server instance.","medium"),
        @("SQL Server must protect against a user falsely repudiating by having performed organization-defined actions.","medium"),
        @("SQL Server must generate Trace or Audit records when unsuccessful attempts to access privileges occur.","low"),
        @("The role(s)/group(s) used to modify database structure and logic must be restricted to authorized users.","medium")
    )
}

$mssql2016database = @{
    DisplayName = "MS SQL Server 2016 Database"; StigId = "MS_SQL_Server_2016_Database_STIG"
    StigName = "MS SQL Server 2016 Database Security Technical Implementation Guide"
    ReleaseInfo = "Release: 4 Benchmark Date: 24 Jan 2026"; Version = "2"; ModuleName = "Scan-MSSQLServer2016Database_Checks"
    TechName = "the SQL Server database"
    Topics = New-TopicList -Code "SQL6D" -Items @(
        @("SQL Server must maintain a separate execution domain for each executing process.","medium"),
        @("SQL Server must protect the confidentiality and integrity of all information at rest.","high"),
        @("SQL Server must generate audit records when unsuccessful attempts to delete privileges/permissions occur.","medium"),
        @("SQL Server must utilize its own account management capabilities and coordinate with enterprise-level account management capabilities.","medium"),
        @("Database objects must be owned by database/DBMS principals authorized for ownership.","low"),
        @("SQL Server must recognize only system-generated session identifiers.","medium")
    )
}

$postgresql9x = @{
    DisplayName = "PostgreSQL 9.x"; StigId = "PostgreSQL_9-x_STIG"
    StigName = "PostgreSQL 9.x Security Technical Implementation Guide"
    ReleaseInfo = "Release: 10 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-PostgreSQL9x_Checks"
    TechName = "the PostgreSQL database"
    Topics = New-TopicList -Code "PGS9" -Items @(
        @("PostgreSQL must limit privileges to change software modules.","medium"),
        @("PostgreSQL must enforce access restrictions associated with changes to the configuration of the database.","medium"),
        @("PostgreSQL must use FIPS 140-2/140-3 approved cryptography for hashing.","high"),
        @("PostgreSQL must generate audit records when privileges/permissions are retrieved.","low"),
        @("PostgreSQL must limit the number of concurrent sessions for each system account.","medium"),
        @("PostgreSQL must produce audit records containing sufficient information to establish the identity of any user/subject associated with the event.","medium")
    )
}

$ciscoswndm = @{
    DisplayName = "Cisco IOS Switch NDM"; StigId = "Cisco_IOS_Switch_NDM_STIG"
    StigName = "Cisco IOS Switch NDM Security Technical Implementation Guide"
    ReleaseInfo = "Release: 4 Benchmark Date: 24 Jan 2026"; Version = "3"; ModuleName = "Scan-CiscoIOSSwitchNDM_Checks"
    TechName = "the Cisco IOS switch"
    Topics = New-TopicList -Code "CISCND" -Items @(
        @("The Cisco switch must be configured to limit the number of concurrent management sessions to an organization-defined number.","medium"),
        @("The Cisco switch must be configured to authenticate all NTP messages received from NTP servers and peers.","medium"),
        @("The Cisco switch must be configured to enforce the limit of three consecutive invalid logon attempts.","medium"),
        @("The Cisco switch must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access.","medium"),
        @("The Cisco switch must be configured to use SSHv2 for administrative access and disable Telnet.","high"),
        @("The Cisco switch must be configured to authenticate SNMP messages using a FIPS-validated HMAC.","medium")
    )
}

$ciscoswl2s = @{
    DisplayName = "Cisco IOS Switch L2S"; StigId = "Cisco_IOS_Switch_L2S_STIG"
    StigName = "Cisco IOS Switch L2S Security Technical Implementation Guide"
    ReleaseInfo = "Release: 4 Benchmark Date: 24 Jan 2026"; Version = "3"; ModuleName = "Scan-CiscoIOSSwitchL2S_Checks"
    TechName = "the Cisco IOS switch"
    Topics = New-TopicList -Code "CISCL2" -Items @(
        @("The Cisco switch must have all disabled switch ports assigned to an unused VLAN.","medium"),
        @("The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches.","medium"),
        @("The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.","high"),
        @("The Cisco switch must have all trunk links enabled statically and use a non-default native VLAN.","medium"),
        @("The Cisco switch must have DHCP snooping enabled on all user VLANs.","medium"),
        @("The Cisco switch must have Dynamic ARP Inspection enabled on all user VLANs.","medium")
    )
}

$ciscortrndm = @{
    DisplayName = "Cisco IOS Router NDM"; StigId = "Cisco_IOS_Router_NDM_STIG"
    StigName = "Cisco IOS Router NDM Security Technical Implementation Guide"
    ReleaseInfo = "Release: 4 Benchmark Date: 24 Jan 2026"; Version = "3"; ModuleName = "Scan-CiscoIOSRouterNDM_Checks"
    TechName = "the Cisco IOS router"
    Topics = New-TopicList -Code "CISRND" -Items @(
        @("The Cisco router must be configured to limit the number of concurrent management sessions.","medium"),
        @("The Cisco router must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access.","medium"),
        @("The Cisco router must be configured to use SSHv2 for administrative access and disable Telnet.","high"),
        @("The Cisco router must be configured to authenticate NTP messages received from NTP servers and peers.","medium"),
        @("The Cisco router must be configured to send log data to a central log server for analysis and reporting.","medium"),
        @("The Cisco router must enforce the limit of three consecutive invalid logon attempts.","medium")
    )
}

$ciscortrrtr = @{
    DisplayName = "Cisco IOS Router RTR"; StigId = "Cisco_IOS_Router_RTR_STIG"
    StigName = "Cisco IOS Router RTR Security Technical Implementation Guide"
    ReleaseInfo = "Release: 4 Benchmark Date: 24 Jan 2026"; Version = "3"; ModuleName = "Scan-CiscoIOSRouterRTR_Checks"
    TechName = "the Cisco IOS router"
    Topics = New-TopicList -Code "CISRRT" -Items @(
        @("The Cisco router must be configured to enforce approved authorizations for controlling the flow of information within the network.","high"),
        @("The Cisco router must be configured to have Gratuitous ARP disabled on all external interfaces.","medium"),
        @("The Cisco router must not be configured to use IP source routing.","medium"),
        @("The Cisco router must be configured to have all inactive interfaces disabled.","low"),
        @("The Cisco router must be configured to enable Unicast Reverse Path Forwarding on all external interfaces.","medium"),
        @("The Cisco router must not be configured with any fastswitching feature that provides a Denial of Service (DoS) or spoofing attack vector.","medium")
    )
}

$f5bigip = @{
    DisplayName = "F5 BIG-IP Device Management"; StigId = "F5_BIG-IP_Device_Management_STIG"
    StigName = "F5 BIG-IP Device Management Security Technical Implementation Guide"
    ReleaseInfo = "Release: 3 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-F5BIGIPDeviceMgmt_Checks"
    TechName = "the F5 BIG-IP appliance"
    Topics = New-TopicList -Code "F5BI" -Items @(
        @("The BIG-IP Core implementation must be configured to authenticate all endpoint devices before establishing a network connection.","medium"),
        @("The BIG-IP Core implementation must be configured to generate log records for management interface access.","medium"),
        @("The BIG-IP Core implementation must enforce approved authorizations for controlling the flow of information between interconnected systems.","high"),
        @("The BIG-IP Core implementation must use FIPS-validated cryptography to protect the confidentiality of remote management sessions.","high"),
        @("The BIG-IP Core implementation must terminate all network connections associated with a device management session at the end of the session.","low"),
        @("The BIG-IP Core implementation must synchronize internal clocks with an authoritative DoD time source.","medium")
    )
}

$paloaltoalg = @{
    DisplayName = "Palo Alto Networks ALG"; StigId = "Palo_Alto_Networks_ALG_STIG"
    StigName = "Palo Alto Networks ALG Security Technical Implementation Guide"
    ReleaseInfo = "Release: 3 Benchmark Date: 24 Jan 2026"; Version = "3"; ModuleName = "Scan-PaloAltoALG_Checks"
    TechName = "the Palo Alto Networks firewall"
    Topics = New-TopicList -Code "PANWAG" -Items @(
        @("The Palo Alto Networks ALG must be configured to generate a log record when administrator access is granted to a management interface.","medium"),
        @("The Palo Alto Networks ALG must be configured to use TLS 1.2 for all remote administrative management sessions.","high"),
        @("The Palo Alto Networks ALG must deny outbound IP packets that contain an illegitimate address in the source address field.","medium"),
        @("The Palo Alto Networks ALG must generate a log record for denied or dropped traffic that terminates or blocks communications sessions.","low"),
        @("The Palo Alto Networks ALG must integrate with an authentication server to authenticate administrators before granting access.","medium"),
        @("The Palo Alto Networks ALG providing intermediary services for remote access must ensure inbound and outbound traffic is monitored for compliance with remote access security policy.","high")
    )
}

$paloaltogp = @{
    DisplayName = "Palo Alto Networks GlobalProtect Gateway"; StigId = "Palo_Alto_Networks_GlobalProtect_Gateway_STIG"
    StigName = "Palo Alto Networks GlobalProtect Gateway Security Technical Implementation Guide"
    ReleaseInfo = "Release: 2 Benchmark Date: 26 Feb 2026"; Version = "1"; ModuleName = "Scan-PaloAltoGlobalProtect_Checks"
    TechName = "the Palo Alto Networks GlobalProtect VPN gateway"
    Topics = New-TopicList -Code "PANWGP" -Items @(
        @("The Palo Alto Networks GlobalProtect Gateway must be configured to use DoD PKI-issued certificates for client authentication.","high"),
        @("The Palo Alto Networks GlobalProtect Gateway must terminate all VPN sessions after a period of inactivity.","medium"),
        @("The Palo Alto Networks GlobalProtect Gateway must enforce split-tunnel restrictions in accordance with organizational policy.","medium"),
        @("The Palo Alto Networks GlobalProtect Gateway must be configured to require multifactor authentication for remote access.","high"),
        @("The Palo Alto Networks GlobalProtect Gateway must log all remote access connection attempts.","low"),
        @("The Palo Alto Networks GlobalProtect Gateway must use FIPS-validated cryptographic modules for all remote access encryption.","high")
    )
}

$esxi = @{
    DisplayName = "VMware vSphere 8.0 ESXi"; StigId = "VMware_vSphere_8-0_ESXi_STIG"
    StigName = "VMware vSphere 8.0 ESXi Security Technical Implementation Guide"
    ReleaseInfo = "Release: 2 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-VMwarevSphere8ESXi_Checks"
    TechName = "the ESXi host"
    Topics = New-TopicList -Code "ESXI80" -Items @(
        @("The ESXi host must enable Bridge Protocol Data Unit (BPDU) filter to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled.","medium"),
        @("The ESXi host must configure the firewall to restrict access to services running on the host.","medium"),
        @("The ESXi host must enable lockdown mode.","high"),
        @("The ESXi host must not be configured to override the default NTP settings.","low"),
        @("The ESXi host must enable strict x509 verification for SSL syslog endpoints.","medium"),
        @("The ESXi host must exclusively use the Enterprise PKI or an approved third-party PKI for TLS certificates.","high")
    )
}

$vcenter = @{
    DisplayName = "VMware vSphere 8.0 vCenter Server"; StigId = "VMware_vSphere_8-0_vCenter_Server_STIG"
    StigName = "VMware vSphere 8.0 vCenter Server Security Technical Implementation Guide"
    ReleaseInfo = "Release: 2 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-VMwarevSphere8vCenter_Checks"
    TechName = "the vCenter Server"
    Topics = New-TopicList -Code "VCTR80" -Items @(
        @("The vCenter Server must enforce a minimum 15-character password length for local accounts.","medium"),
        @("The vCenter Server must be configured to integrate with an existing DoD-approved single sign-on or authentication server.","high"),
        @("The vCenter Server must be configured to send logs to a central log server.","medium"),
        @("The vCenter Server must enable audit logging for all administrative actions.","medium"),
        @("The vCenter Server must limit the number of concurrent sessions for administrative accounts.","low"),
        @("The vCenter Server must use the Enterprise PKI or approved third-party PKI for TLS certificates.","high")
    )
}

$win11 = @{
    DisplayName = "Microsoft Windows 11"; StigId = "Windows_11_STIG"
    StigName = "Microsoft Windows 11 Security Technical Implementation Guide"
    ReleaseInfo = "Release: 4 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-Windows11_Checks"
    TechName = "the Windows 11 workstation"
    Topics = New-TopicList -Code "WN11" -Items @(
        @("Windows 11 systems must use a BitLocker PIN for pre-boot authentication.","high"),
        @("Windows 11 must be configured to require a minimum PIN length of six characters or greater.","medium"),
        @("Windows 11 must prevent the display of slide shows on the lock screen.","low"),
        @("Windows 11 users must be required to have a password for the screen saver to be enabled.","medium"),
        @("Windows 11 must not allow Autoplay to run for removable media.","low"),
        @("Windows 11 must be configured to disable Windows Game Recording and Broadcasting.","low")
    )
}

$win10 = @{
    DisplayName = "Microsoft Windows 10"; StigId = "Windows_10_STIG"
    StigName = "Microsoft Windows 10 Security Technical Implementation Guide"
    ReleaseInfo = "Release: 8 Benchmark Date: 26 Feb 2026"; Version = "3"; ModuleName = "Scan-Windows10_Checks"
    TechName = "the Windows 10 workstation"
    Topics = New-TopicList -Code "WN10" -Items @(
        @("Windows 10 systems must use a BitLocker PIN for pre-boot authentication.","high"),
        @("Windows 10 must be configured to require a minimum PIN length of six characters or greater.","medium"),
        @("Windows 10 must prevent the display of slide shows on the lock screen.","low"),
        @("Windows 10 users must be required to have a password for the screen saver to be enabled.","medium"),
        @("Windows 10 must not allow Autoplay to run for removable media.","low"),
        @("Windows 10 must be configured to disable Windows Game Recording and Broadcasting.","low")
    )
}

$office365 = @{
    DisplayName = "Microsoft Office 365 ProPlus"; StigId = "Microsoft_Office_365_ProPlus_STIG"
    StigName = "Microsoft Office 365 ProPlus Security Technical Implementation Guide"
    ReleaseInfo = "Release: 5 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-Office365ProPlus_Checks"
    TechName = "Microsoft Office 365 ProPlus"
    Topics = New-TopicList -Code "O365" -Items @(
        @("Microsoft Office 365 ProPlus must have Macro Runtime Scan Scope enabled for all Office applications.","high"),
        @("Microsoft Outlook must have Object Model Guard set for Send.","medium"),
        @("Microsoft Office 365 ProPlus must disable Trust Bar Notifications for unsigned application add-ins in all Office applications.","medium"),
        @("Microsoft Office 365 ProPlus must have Block macros from running in Office files from the Internet enabled.","high"),
        @("Microsoft Excel must have Excel 4.0 macros disabled.","medium"),
        @("Microsoft Office 365 ProPlus must prevent Office applications from creating child processes.","medium")
    )
}

$rhel9 = @{
    DisplayName = "Red Hat Enterprise Linux 9"; StigId = "RHEL_9_STIG"
    StigName = "Red Hat Enterprise Linux 9 Security Technical Implementation Guide"
    ReleaseInfo = "Release: 3 Benchmark Date: 26 Feb 2026"; Version = "9.8"; ModuleName = "Scan-RHEL9_Checks"
    TechName = "the RHEL 9 host"
    Topics = New-TopicList -Code "RHEL09" -Items @(
        @("RHEL 9 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.","medium"),
        @("RHEL 9 must enable FIPS mode.","high"),
        @("RHEL 9 must not have the telnet-server package installed.","high"),
        @("RHEL 9 must configure SELinux to be enabled and in enforcing mode.","high"),
        @("RHEL 9 must ensure the password complexity module is enabled in the system-auth file.","medium"),
        @("RHEL 9 must automatically lock an account until released by an administrator when three unsuccessful logon attempts occur.","medium"),
        @("RHEL 9 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access.","low"),
        @("RHEL 9 must remove all software components after updated versions have been installed.","low")
    )
}

$ubuntu2204 = @{
    DisplayName = "Canonical Ubuntu 22.04 LTS"; StigId = "Canonical_Ubuntu_22-04_LTS_STIG"
    StigName = "Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide"
    ReleaseInfo = "Release: 3 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-Ubuntu2204_Checks"
    TechName = "the Ubuntu 22.04 host"
    Topics = New-TopicList -Code "UBTU22" -Items @(
        @("Ubuntu 22.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.","medium"),
        @("Ubuntu 22.04 LTS must have the openssh-server package configured to reject weak ciphers.","high"),
        @("Ubuntu 22.04 LTS must not have the telnet package installed.","high"),
        @("Ubuntu 22.04 LTS must have AppArmor enabled and enforcing.","high"),
        @("Ubuntu 22.04 LTS must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access.","low"),
        @("Ubuntu 22.04 LTS must remove all software components after updated versions have been installed.","low")
    )
}

$firefox = @{
    DisplayName = "Mozilla Firefox"; StigId = "Mozilla_Firefox_STIG"
    StigName = "Mozilla Firefox Security Technical Implementation Guide"
    ReleaseInfo = "Release: 7 Benchmark Date: 26 Feb 2026"; Version = "6"; ModuleName = "Scan-MozillaFirefox_Checks"
    TechName = "the Mozilla Firefox browser"
    Topics = New-TopicList -Code "FFOX" -Items @(
        @("Mozilla Firefox must be configured to disallow websites from disabling the ability to override certificate warnings.","high"),
        @("Mozilla Firefox must be configured to not automatically check for updates.","medium"),
        @("Mozilla Firefox must have the Enterprise Policy Enabled.","medium"),
        @("Mozilla Firefox must have the DNS-over-HTTPS feature disabled.","medium"),
        @("Mozilla Firefox must be configured to disable AutoFill of passwords.","low"),
        @("Mozilla Firefox must have Extension Recommendations disabled.","low")
    )
}

$kubernetes = @{
    DisplayName = "Kubernetes"; StigId = "Kubernetes_STIG"
    StigName = "Kubernetes Security Technical Implementation Guide"
    ReleaseInfo = "Release: 4 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-Kubernetes_Checks"
    TechName = "the Kubernetes node"
    Topics = New-TopicList -Code "K8S" -Items @(
        @("Kubernetes API Server must have anonymous authentication disabled.","high"),
        @("Kubernetes Kubelet must enable kernel protection.","medium"),
        @("Kubernetes must separate user functionality.","medium"),
        @("Kubernetes etcd must have secure client transport (client-cert-auth) enabled for all communications.","high"),
        @("The Kubernetes API server must have an audit log path set.","medium"),
        @("Kubernetes must have a Pod Security Admission control file configured.","medium")
    )
}

$dockerent = @{
    DisplayName = "Docker Enterprise 2.x Linux/UNIX"; StigId = "Docker_Enterprise_2-x_Linux-UNIX_STIG"
    StigName = "Docker Enterprise 2.x Linux/UNIX Security Technical Implementation Guide"
    ReleaseInfo = "Release: 2 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-DockerEnterprise_Checks"
    TechName = "the Docker Enterprise host"
    Topics = New-TopicList -Code "DKER" -Items @(
        @("Docker Enterprise must remap the default user to a non-privileged user at daemon start.","high"),
        @("Docker Enterprise must set the logging level to the appropriate level.","low"),
        @("Docker Enterprise must restrict container's ability to acquire additional privileges.","high"),
        @("Docker Enterprise must not use privileged containers unless explicitly documented.","high"),
        @("Docker Enterprise must implement encryption for TLS to protect the confidentiality of remote sessions.","medium"),
        @("Docker Enterprise must be configured to generate audit records for all account creations, modifications, disabling, and terminations.","medium")
    )
}

$nginx = @{
    DisplayName = "NGINX Web Server"; StigId = "NGINX_Web_Server_STIG"
    StigName = "NGINX Web Server Security Technical Implementation Guide"
    ReleaseInfo = "Release: 1 Benchmark Date: 26 Feb 2026"; Version = "1"; ModuleName = "Scan-NGINXWebServer_Checks"
    TechName = "the NGINX web server"
    Topics = New-TopicList -Code "NGNX" -Items @(
        @("NGINX Web Server must enforce approved authorizations for controlling access between the web server and backend applications.","medium"),
        @("NGINX Web Server must generate log records for access attempts to security objects.","medium"),
        @("NGINX Web Server must use TLS 1.2 or higher for all client connections.","high"),
        @("NGINX Web Server must not have unnecessary modules enabled.","low"),
        @("NGINX Web Server must be configured to limit the number of allowed simultaneous session requests.","medium"),
        @("NGINX Web Server must redirect HTTP requests to HTTPS.","medium")
    )
}

$apachetomcat = @{
    DisplayName = "Apache Tomcat Application Server 10"; StigId = "Apache_Tomcat_10_STIG"
    StigName = "Apache Tomcat Application Server 10 Security Technical Implementation Guide"
    ReleaseInfo = "Release: 1 Benchmark Date: 24 Jan 2026"; Version = "1"; ModuleName = "Scan-ApacheTomcat10_Checks"
    TechName = "the Apache Tomcat server"
    Topics = New-TopicList -Code "TCAT" -Items @(
        @("Apache Tomcat must set the allowLinking attribute to false.","medium"),
        @("Apache Tomcat must have the debug flag disabled for servlets.","low"),
        @("Apache Tomcat must not have the Manager application deployed.","high"),
        @("Apache Tomcat must be configured to limit the number of allowed simultaneous session control.","medium"),
        @("Apache Tomcat must have the shutdown port disabled.","medium"),
        @("Apache Tomcat must be configured to redirect HTTP requests to HTTPS.","medium"),
        @("Apache Tomcat must use TLS 1.2 or higher for all connectors.","high"),
        @("Apache Tomcat must have the default error page suppress the Tomcat version banner.","low")
    )
}

$winsvrdns = @{
    DisplayName = "Windows Server 2022 DNS"; StigId = "Windows_Server_2022_DNS_STIG"
    StigName = "Microsoft Windows Server 2022 DNS Security Technical Implementation Guide"
    ReleaseInfo = "Release: 2 Benchmark Date: 26 Feb 2026"; Version = "1"; ModuleName = "Scan-WindowsServer2022DNS_Checks"
    TechName = "the Windows Server 2022 DNS role"
    Topics = New-TopicList -Code "DNSS" -Items @(
        @("Windows Server 2022 DNS Server must have DNSSEC validation enabled.","high"),
        @("Windows Server 2022 DNS Server must limit the number of concurrent zone transfer requests.","medium"),
        @("Windows Server 2022 DNS Server must be configured to only allow zone transfers to authorized secondary servers.","high"),
        @("Windows Server 2022 DNS Server must log all query and response traffic for auditing purposes.","medium"),
        @("Windows Server 2022 DNS Server must disable recursion on authoritative name servers exposed to untrusted networks.","medium"),
        @("Windows Server 2022 DNS Server must be configured to use only DoD-approved root hints.","low")
    )
}

$exchmailbox = @{
    DisplayName = "Microsoft Exchange 2019 Mailbox Server"; StigId = "MS_Exchange_2019_Mailbox_Server_STIG"
    StigName = "Microsoft Exchange 2019 Mailbox Server Security Technical Implementation Guide"
    ReleaseInfo = "Release: 3 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-Exchange2019Mailbox_Checks"
    TechName = "the Exchange Mailbox server"
    Topics = New-TopicList -Code "EX19M" -Items @(
        @("Exchange Mailbox Server must have Send Fatal Errors to Microsoft disabled.","low"),
        @("Exchange Mailbox Server must have anonymous relay disabled on all Receive Connectors.","high"),
        @("Exchange Mailbox Server must have the maximum number of recipients per message set in accordance with organizational policy.","medium"),
        @("Exchange Mailbox Server must enable Transport Layer Security (TLS) for all inbound and outbound SMTP connections.","high"),
        @("Exchange Mailbox Server must have auditing enabled for mailbox access.","medium"),
        @("Exchange Mailbox Server must limit the size of email attachments in accordance with organizational policy.","medium")
    )
}

$exchedge = @{
    DisplayName = "Microsoft Exchange 2019 Edge Transport Server"; StigId = "MS_Exchange_2019_Edge_Transport_STIG"
    StigName = "Microsoft Exchange 2019 Edge Transport Server Security Technical Implementation Guide"
    ReleaseInfo = "Release: 3 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-Exchange2019Edge_Checks"
    TechName = "the Exchange Edge Transport server"
    Topics = New-TopicList -Code "EX19E" -Items @(
        @("Exchange Edge Transport Server must have anti-spam filtering enabled.","medium"),
        @("Exchange Edge Transport Server must not relay email for domains it does not host.","high"),
        @("Exchange Edge Transport Server must be configured to require TLS for all inbound connections from external hosts.","high"),
        @("Exchange Edge Transport Server must log all message tracking data.","medium"),
        @("Exchange Edge Transport Server must have attachment filtering enabled to block executable content.","medium"),
        @("Exchange Edge Transport Server must be placed in a DMZ segment separate from internal mail infrastructure.","low")
    )
}

$iosmdm = @{
    DisplayName = "Apple iOS/iPadOS 17"; StigId = "Apple_iOS-iPadOS_17_STIG"
    StigName = "Apple iOS/iPadOS 17 Security Technical Implementation Guide"
    ReleaseInfo = "Release: 3 Benchmark Date: 26 Feb 2026"; Version = "2"; ModuleName = "Scan-AppleiOS17_Checks"
    TechName = "the Apple iOS/iPadOS device"
    Topics = New-TopicList -Code "AIOS" -Items @(
        @("Apple iOS/iPadOS must be configured to disable the camera when the device is used in a classified area.","low"),
        @("Apple iOS/iPadOS must be configured to require a passcode for device unlock.","high"),
        @("Apple iOS/iPadOS must have automatic backup to iCloud disabled.","medium"),
        @("Apple iOS/iPadOS must have the maximum passcode age set to 60 days or less.","medium"),
        @("Apple iOS/iPadOS must have USB restricted mode enabled.","medium"),
        @("Apple iOS/iPadOS must be enrolled in the organization's Mobile Device Management (MDM) solution.","high")
    )
}

$androidmdm = @{
    DisplayName = "Google Android 14"; StigId = "Google_Android_14_STIG"
    StigName = "Google Android 14 Security Technical Implementation Guide"
    ReleaseInfo = "Release: 2 Benchmark Date: 26 Feb 2026"; Version = "1"; ModuleName = "Scan-GoogleAndroid14_Checks"
    TechName = "the Google Android device"
    Topics = New-TopicList -Code "GAND" -Items @(
        @("Google Android must be configured to require a passcode/PIN/pattern for device unlock.","high"),
        @("Google Android must have USB debugging disabled.","medium"),
        @("Google Android must have unknown sources (sideloading) disabled.","high"),
        @("Google Android must be enrolled in the organization's Mobile Device Management (MDM) solution.","high"),
        @("Google Android must have the maximum passcode age set to 60 days or less.","medium"),
        @("Google Android must have full-device encryption enabled.","high")
    )
}

$macos = @{
    DisplayName = "Apple macOS 14 (Sonoma)"; StigId = "Apple_macOS_14_STIG"
    StigName = "Apple macOS 14 (Sonoma) Security Technical Implementation Guide"
    ReleaseInfo = "Release: 2 Benchmark Date: 26 Feb 2026"; Version = "1"; ModuleName = "Scan-AppleMacOS14_Checks"
    TechName = "the macOS workstation"
    Topics = New-TopicList -Code "AOSX" -Items @(
        @("macOS must be configured to lock the screen after a defined period of inactivity.","medium"),
        @("macOS must have FileVault full-disk encryption enabled.","high"),
        @("macOS must be configured to disable the guest account.","medium"),
        @("macOS must have Gatekeeper enabled to only allow signed and verified applications to execute.","high"),
        @("macOS must be configured to require an administrator password to install or update software.","medium"),
        @("macOS must have automatic login disabled.","medium")
    )
}

# ===========================================================================
# 58 asset instances
# ===========================================================================

# --- Domain controllers (4) ---
New-Asset -FileName "dc02-win2022.cklb" -HostName "DC02-WIN2022" -IpAddress (Next-Ip "10.10.0" 11) -MacAddress (Next-Mac) -Fqdn "dc02-win2022.utsec.mil" -Role "Domain Controller" -TechArea "Directory Services" -ProfileList @($winserver2022,$addsstig)
New-Asset -FileName "dc03-win2022.cklb" -HostName "DC03-WIN2022" -IpAddress (Next-Ip "10.10.0") -MacAddress (Next-Mac) -Fqdn "dc03-win2022.utsec.mil" -Role "Domain Controller" -TechArea "Directory Services" -ProfileList @($winserver2022,$addsstig)
New-Asset -FileName "dc04-win2022.cklb" -HostName "DC04-WIN2022" -IpAddress (Next-Ip "10.10.0") -MacAddress (Next-Mac) -Fqdn "dc04-win2022.utsec.mil" -Role "Domain Controller" -TechArea "Directory Services" -ProfileList @($winserver2022,$addsstig)
New-Asset -FileName "dc05-win2019.cklb" -HostName "DC05-WIN2019" -IpAddress (Next-Ip "10.10.0") -MacAddress (Next-Mac) -Fqdn "dc05-win2019.utsec.mil" -Role "Domain Controller" -TechArea "Directory Services" -ProfileList @($winserver2019,$addsstig)

# --- SQL servers (5) ---
New-Asset -FileName "db-sql02.cklb" -HostName "DB-SQL02" -IpAddress (Next-Ip "10.20.2" 32) -MacAddress (Next-Mac) -Fqdn "db-sql02.utsec.mil" -Role "Member Server" -TechArea "Database" -IsWebDb $true -ProfileList @($winserver2022,$mssql2016instance)
New-Asset -FileName "db-sql03.cklb" -HostName "DB-SQL03" -IpAddress (Next-Ip "10.20.2") -MacAddress (Next-Mac) -Fqdn "db-sql03.utsec.mil" -Role "Member Server" -TechArea "Database" -IsWebDb $true -ProfileList @($winserver2022,$mssql2016instance)
New-Asset -FileName "db-sql04.cklb" -HostName "DB-SQL04" -IpAddress (Next-Ip "10.20.2") -MacAddress (Next-Mac) -Fqdn "db-sql04.utsec.mil" -Role "Member Server" -TechArea "Database" -IsWebDb $true -ProfileList @($winserver2022,$mssql2016instance)
New-Asset -FileName "db-sql05.cklb" -HostName "DB-SQL05" -IpAddress (Next-Ip "10.20.2") -MacAddress (Next-Mac) -Fqdn "db-sql05.utsec.mil" -Role "Member Server" -TechArea "Database" -IsWebDb $true -ProfileList @($winserver2022,$mssql2016database)
New-Asset -FileName "db-sql06.cklb" -HostName "DB-SQL06" -IpAddress (Next-Ip "10.20.2") -MacAddress (Next-Mac) -Fqdn "db-sql06.utsec.mil" -Role "Member Server" -TechArea "Database" -IsWebDb $true -ProfileList @($winserver2019,$mssql2016instance)

# --- PostgreSQL servers (3) ---
New-Asset -FileName "db-pg01.cklb" -HostName "DB-PG01" -IpAddress (Next-Ip "10.20.2" 51) -MacAddress (Next-Mac) -Fqdn "db-pg01.utsec.mil" -Role "Member Server" -TechArea "Database" -IsWebDb $true -ProfileList @($rhel9,$postgresql9x)
New-Asset -FileName "db-pg02.cklb" -HostName "DB-PG02" -IpAddress (Next-Ip "10.20.2") -MacAddress (Next-Mac) -Fqdn "db-pg02.utsec.mil" -Role "Member Server" -TechArea "Database" -IsWebDb $true -ProfileList @($rhel9,$postgresql9x)
New-Asset -FileName "db-pg03.cklb" -HostName "DB-PG03" -IpAddress (Next-Ip "10.20.2") -MacAddress (Next-Mac) -Fqdn "db-pg03.utsec.mil" -Role "Member Server" -TechArea "Database" -IsWebDb $true -ProfileList @($rhel9,$postgresql9x)

# --- Switches (8, NDM + L2S combined) ---
New-Asset -FileName "sw-core-02.cklb" -HostName "SW-CORE-02" -IpAddress (Next-Ip "10.10.1" 3) -MacAddress (Next-Mac) -Fqdn "sw-core-02.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoswndm,$ciscoswl2s)
New-Asset -FileName "sw-access-15.cklb" -HostName "SW-ACCESS-15" -IpAddress (Next-Ip "10.10.4" 15) -MacAddress (Next-Mac) -Fqdn "sw-access-15.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoswndm,$ciscoswl2s)
New-Asset -FileName "sw-access-16.cklb" -HostName "SW-ACCESS-16" -IpAddress (Next-Ip "10.10.4") -MacAddress (Next-Mac) -Fqdn "sw-access-16.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoswndm,$ciscoswl2s)
New-Asset -FileName "sw-access-17.cklb" -HostName "SW-ACCESS-17" -IpAddress (Next-Ip "10.10.4") -MacAddress (Next-Mac) -Fqdn "sw-access-17.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoswndm,$ciscoswl2s)
New-Asset -FileName "sw-access-18.cklb" -HostName "SW-ACCESS-18" -IpAddress (Next-Ip "10.10.4") -MacAddress (Next-Mac) -Fqdn "sw-access-18.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoswndm,$ciscoswl2s)
New-Asset -FileName "sw-access-19.cklb" -HostName "SW-ACCESS-19" -IpAddress (Next-Ip "10.10.4") -MacAddress (Next-Mac) -Fqdn "sw-access-19.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoswndm,$ciscoswl2s)
New-Asset -FileName "sw-access-20.cklb" -HostName "SW-ACCESS-20" -IpAddress (Next-Ip "10.10.4") -MacAddress (Next-Mac) -Fqdn "sw-access-20.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoswndm,$ciscoswl2s)
New-Asset -FileName "sw-access-21.cklb" -HostName "SW-ACCESS-21" -IpAddress (Next-Ip "10.10.4") -MacAddress (Next-Mac) -Fqdn "sw-access-21.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoswndm,$ciscoswl2s)

# --- Routers (5, NDM + RTR combined) ---
New-Asset -FileName "rtr-edge-01.cklb" -HostName "RTR-EDGE-01" -IpAddress (Next-Ip "10.10.5" 1) -MacAddress (Next-Mac) -Fqdn "rtr-edge-01.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscortrndm,$ciscortrrtr)
New-Asset -FileName "rtr-edge-02.cklb" -HostName "RTR-EDGE-02" -IpAddress (Next-Ip "10.10.5") -MacAddress (Next-Mac) -Fqdn "rtr-edge-02.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscortrndm,$ciscortrrtr)
New-Asset -FileName "rtr-core-03.cklb" -HostName "RTR-CORE-03" -IpAddress (Next-Ip "10.10.5") -MacAddress (Next-Mac) -Fqdn "rtr-core-03.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscortrndm,$ciscortrrtr)
New-Asset -FileName "rtr-branch-04.cklb" -HostName "RTR-BRANCH-04" -IpAddress (Next-Ip "10.10.5") -MacAddress (Next-Mac) -Fqdn "rtr-branch-04.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscortrndm,$ciscortrrtr)
New-Asset -FileName "rtr-branch-05.cklb" -HostName "RTR-BRANCH-05" -IpAddress (Next-Ip "10.10.5") -MacAddress (Next-Mac) -Fqdn "rtr-branch-05.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscortrndm,$ciscortrrtr)

# --- Load balancers (2) ---
New-Asset -FileName "lb-f5-01.cklb" -HostName "LB-F5-01" -IpAddress (Next-Ip "10.10.6" 1) -MacAddress (Next-Mac) -Fqdn "lb-f5-01.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($f5bigip)
New-Asset -FileName "lb-f5-02.cklb" -HostName "LB-F5-02" -IpAddress (Next-Ip "10.10.6") -MacAddress (Next-Mac) -Fqdn "lb-f5-02.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($f5bigip)

# --- Firewalls / VPN gateway (3) ---
New-Asset -FileName "fw-perim-03.cklb" -HostName "FW-PERIM-03" -IpAddress "203.0.113.3" -MacAddress (Next-Mac) -Fqdn "fw-perim-03.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($paloaltoalg)
New-Asset -FileName "fw-branch-04.cklb" -HostName "FW-BRANCH-04" -IpAddress "203.0.113.4" -MacAddress (Next-Mac) -Fqdn "fw-branch-04.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($paloaltoalg)
New-Asset -FileName "vpn-gw-01.cklb" -HostName "VPN-GW-01" -IpAddress "203.0.113.5" -MacAddress (Next-Mac) -Fqdn "vpn-gw-01.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($paloaltogp)

# --- ESXi hosts + vCenter (4) ---
New-Asset -FileName "esxi-host-04.cklb" -HostName "ESXI-HOST-04" -IpAddress (Next-Ip "10.10.2" 14) -MacAddress (Next-Mac "00:50:56") -Fqdn "esxi-host-04.utsec.mil" -Role "None" -TechArea "None" -ProfileList @($esxi)
New-Asset -FileName "esxi-host-05.cklb" -HostName "ESXI-HOST-05" -IpAddress (Next-Ip "10.10.2") -MacAddress (Next-Mac "00:50:56") -Fqdn "esxi-host-05.utsec.mil" -Role "None" -TechArea "None" -ProfileList @($esxi)
New-Asset -FileName "esxi-host-06.cklb" -HostName "ESXI-HOST-06" -IpAddress (Next-Ip "10.10.2") -MacAddress (Next-Mac "00:50:56") -Fqdn "esxi-host-06.utsec.mil" -Role "None" -TechArea "None" -ProfileList @($esxi)
New-Asset -FileName "vcenter-01.cklb" -HostName "VCENTER-01" -IpAddress (Next-Ip "10.10.2") -MacAddress (Next-Mac "00:50:56") -Fqdn "vcenter-01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($vcenter)

# --- Windows + Office workstations (5) ---
New-Asset -FileName "wks-05001.cklb" -HostName "WKS-05001" -IpAddress (Next-Ip "10.30.6" 202) -MacAddress (Next-Mac "00:1C:42") -Fqdn "wks-05001.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win11,$office365)
New-Asset -FileName "wks-05002.cklb" -HostName "WKS-05002" -IpAddress (Next-Ip "10.30.6") -MacAddress (Next-Mac "00:1C:42") -Fqdn "wks-05002.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win11,$office365)
New-Asset -FileName "wks-05003.cklb" -HostName "WKS-05003" -IpAddress (Next-Ip "10.30.6") -MacAddress (Next-Mac "00:1C:42") -Fqdn "wks-05003.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win10,$office365)
New-Asset -FileName "wks-05004.cklb" -HostName "WKS-05004" -IpAddress (Next-Ip "10.30.6") -MacAddress (Next-Mac "00:1C:42") -Fqdn "wks-05004.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win10,$office365)
New-Asset -FileName "wks-05005.cklb" -HostName "WKS-05005" -IpAddress (Next-Ip "10.30.6") -MacAddress (Next-Mac "00:1C:42") -Fqdn "wks-05005.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win11,$office365)

# --- Linux developer workstations (3) ---
New-Asset -FileName "devwks-rhel9-01.cklb" -HostName "DEVWKS-RHEL9-01" -IpAddress (Next-Ip "10.30.7" 1) -MacAddress (Next-Mac "00:1C:42") -Fqdn "devwks-rhel9-01.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($rhel9,$firefox)
New-Asset -FileName "devwks-rhel9-02.cklb" -HostName "DEVWKS-RHEL9-02" -IpAddress (Next-Ip "10.30.7") -MacAddress (Next-Mac "00:1C:42") -Fqdn "devwks-rhel9-02.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($rhel9,$firefox)
New-Asset -FileName "devwks-ubuntu-01.cklb" -HostName "DEVWKS-UBUNTU-01" -IpAddress (Next-Ip "10.30.7") -MacAddress (Next-Mac "00:1C:42") -Fqdn "devwks-ubuntu-01.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($ubuntu2204,$firefox)

# --- Exchange mail servers (2) ---
New-Asset -FileName "mail-ex01.cklb" -HostName "MAIL-EX01" -IpAddress (Next-Ip "10.20.3" 11) -MacAddress (Next-Mac) -Fqdn "mail-ex01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($winserver2022,$exchmailbox)
New-Asset -FileName "mail-ex02.cklb" -HostName "MAIL-EX02" -IpAddress (Next-Ip "10.20.3") -MacAddress (Next-Mac) -Fqdn "mail-ex02.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($winserver2022,$exchedge)

# --- Dev shop common services (7) ---
New-Asset -FileName "k8s-worker-02.cklb" -HostName "K8S-WORKER-02" -IpAddress (Next-Ip "10.20.4" 12) -MacAddress (Next-Mac) -Fqdn "k8s-worker-02.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($rhel9,$kubernetes)
New-Asset -FileName "docker-host-01.cklb" -HostName "DOCKER-HOST-01" -IpAddress (Next-Ip "10.20.4") -MacAddress (Next-Mac) -Fqdn "docker-host-01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($ubuntu2204,$dockerent)
New-Asset -FileName "gitlab-01.cklb" -HostName "GITLAB-01" -IpAddress (Next-Ip "10.20.4") -MacAddress (Next-Mac) -Fqdn "gitlab-01.utsec.mil" -Role "Member Server" -TechArea "Web Server" -IsWebDb $true -ProfileList @($rhel9,$nginx)
New-Asset -FileName "ci-jenkins-01.cklb" -HostName "CI-JENKINS-01" -IpAddress (Next-Ip "10.20.4") -MacAddress (Next-Mac) -Fqdn "ci-jenkins-01.utsec.mil" -Role "Member Server" -TechArea "Web Server" -IsWebDb $true -ProfileList @($rhel9,$apachetomcat)
New-Asset -FileName "wiki-01.cklb" -HostName "WIKI-01" -IpAddress (Next-Ip "10.20.4") -MacAddress (Next-Mac) -Fqdn "wiki-01.utsec.mil" -Role "Member Server" -TechArea "Web Server" -IsWebDb $true -ProfileList @($ubuntu2204,$apachetomcat)
New-Asset -FileName "registry-01.cklb" -HostName "REGISTRY-01" -IpAddress (Next-Ip "10.20.4") -MacAddress (Next-Mac) -Fqdn "registry-01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($ubuntu2204,$dockerent)
New-Asset -FileName "cache-redis-01.cklb" -HostName "CACHE-REDIS-01" -IpAddress (Next-Ip "10.20.4") -MacAddress (Next-Mac) -Fqdn "cache-redis-01.utsec.mil" -Role "Member Server" -TechArea "Database" -ProfileList @($rhel9)

# --- File / DNS servers (2) ---
New-Asset -FileName "dns-01.cklb" -HostName "DNS-01" -IpAddress (Next-Ip "10.20.5" 11) -MacAddress (Next-Mac) -Fqdn "dns-01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($winserver2022,$winsvrdns)
New-Asset -FileName "fileserver-01.cklb" -HostName "FILESERVER-01" -IpAddress (Next-Ip "10.20.5") -MacAddress (Next-Mac) -Fqdn "fileserver-01.utsec.mil" -Role "Member Server" -TechArea "File Server" -ProfileList @($winserver2022)

# --- Monitoring (1) ---
New-Asset -FileName "mon-splunk-01.cklb" -HostName "MON-SPLUNK-01" -IpAddress (Next-Ip "10.20.6" 11) -MacAddress (Next-Mac) -Fqdn "mon-splunk-01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($rhel9)

# --- Mobile & endpoint (4) ---
New-Asset -FileName "iphone-corp-014.cklb" -HostName "IPHONE-CORP-014" -IpAddress "" -MacAddress (Next-Mac "AC:DE:48") -Fqdn "" -Role "None" -TechArea "None" -ProfileList @($iosmdm)
New-Asset -FileName "ipad-corp-022.cklb" -HostName "IPAD-CORP-022" -IpAddress "" -MacAddress (Next-Mac "AC:DE:48") -Fqdn "" -Role "None" -TechArea "None" -ProfileList @($iosmdm)
New-Asset -FileName "android-corp-031.cklb" -HostName "ANDROID-CORP-031" -IpAddress "" -MacAddress (Next-Mac "3C:5A:B4") -Fqdn "" -Role "None" -TechArea "None" -ProfileList @($androidmdm)
New-Asset -FileName "macbook-corp-002.cklb" -HostName "MACBOOK-CORP-002" -IpAddress (Next-Ip "10.30.8" 1) -MacAddress (Next-Mac "AC:DE:48") -Fqdn "macbook-corp-002.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($macos)

Write-Output "DONE"
