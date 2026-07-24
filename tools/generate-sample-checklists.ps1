<#
.SYNOPSIS
    Generates realistic Evaluate-STIG-style .cklb sample checklists for the
    dashboard's "sample checklists" folder, using real DISA XCCDF benchmark
    content instead of hand-typed sample findings.

.DESCRIPTION
    Parses full XCCDF benchmark XML files from tools/stigs/ (every Group/Rule,
    every real title, severity, discussion, fix text, check text, and CCI) and
    builds structurally-valid CKLB (JSON) checklists against that real rule
    set for a small library of fake hosts.

    Each host is assigned a ComplianceWeight (0.0-1.0) that drives how likely
    each of its findings is to come back NotAFinding vs Open, so hosts don't
    all converge on nearly the same compliance percentage. Not_Applicable and
    Not_Reviewed are assigned first from flat/weight-adjusted probabilities,
    and the remaining findings split Open/NotAFinding using the host's
    ComplianceWeight, further adjusted per-rule by severity (CAT I findings
    remediate slower than CAT III even on well-run hosts). All rolls are
    seeded from hostname+STIG so results are reproducible across re-runs.

.NOTES
    Re-running this script overwrites any existing files of the same name in
    the output folder. To add more sample assets:
      1. Add the STIG's XCCDF xml file to tools/stigs/ if not already present.
      2. Register a profile for it (see the "STIG profiles" section) - just
         the filename, a human TechName used in narrative text, and a module
         name.
      3. Add a New-Asset call at the bottom referencing that profile and a
         ComplianceWeight for the host.
    Parsed STIG content is cached per-file (module-level $script:stigCache)
    so adding many hosts that share a STIG only parses that XML once.

.EXAMPLE
    pwsh ./tools/generate-sample-checklists.ps1
#>

$ErrorActionPreference = "Stop"
$outDir = Join-Path $PSScriptRoot "..\sample checklists"
$stigsDir = Join-Path $PSScriptRoot "stigs"
$scanDate = (Get-Date).ToString("MM/dd/yyyy")
$scanTimeBase = Get-Date

# ===========================================================================
# Low-level helpers
# ===========================================================================

function New-Hash {
    -join ((1..40) | ForEach-Object { "{0:X}" -f (Get-Random -Maximum 16) })
}

function Get-StableHash([string]$s) {
    $h = 0
    foreach ($c in $s.ToCharArray()) { $h = ($h * 31 + [int][char]$c) -band 0x7FFFFFFF }
    return $h
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
# XCCDF parsing (namespace-agnostic via local-name() so it doesn't matter
# whether the benchmark declares the 1.1 or 1.2 xccdf namespace)
# ===========================================================================

$script:stigCache = @{}

function Get-XccdfStig {
    param([string]$FileName)

    if ($script:stigCache.ContainsKey($FileName)) { return $script:stigCache[$FileName] }

    $path = Join-Path $stigsDir $FileName
    if (-not (Test-Path $path)) { throw "STIG source file not found: $path" }

    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($path)
    $bench = $xml.SelectSingleNode("//*[local-name()='Benchmark']")
    if (-not $bench) { throw "No <Benchmark> root found in $FileName" }

    $title = ($bench.SelectSingleNode("*[local-name()='title']")).InnerText
    $versionNode = $bench.SelectSingleNode("*[local-name()='version']")
    $version = if ($versionNode) { $versionNode.InnerText } else { "1" }
    $releaseNode = $bench.SelectSingleNode("*[local-name()='plain-text'][@id='release-info']")
    $releaseInfo = if ($releaseNode) { $releaseNode.InnerText } else { "" }
    $stigId = $bench.GetAttribute("id")
    $displayName = [regex]::Replace($title, '\s+Security Technical Implementation Guide\s*$', '')

    $rules = @()
    foreach ($g in $bench.SelectNodes("*[local-name()='Group']")) {
        $rule = $g.SelectSingleNode("*[local-name()='Rule']")
        if (-not $rule) { continue }

        $ruleIdSrc = $rule.GetAttribute("id")
        $ruleIdMatch = [regex]::Match($ruleIdSrc, '^(SV-\d+)')
        $ruleId = if ($ruleIdMatch.Success) { $ruleIdMatch.Groups[1].Value } else { $ruleIdSrc }

        $severity = $rule.GetAttribute("severity")
        if ([string]::IsNullOrEmpty($severity)) { $severity = "medium" }

        $ruleVersionNode = $rule.SelectSingleNode("*[local-name()='version']")
        $ruleVersion = if ($ruleVersionNode) { $ruleVersionNode.InnerText } else { $ruleId }

        $ruleTitleNode = $rule.SelectSingleNode("*[local-name()='title']")
        $ruleTitle = if ($ruleTitleNode) { $ruleTitleNode.InnerText } else { $ruleId }

        $groupTitleNode = $g.SelectSingleNode("*[local-name()='title']")
        $groupTitle = if ($groupTitleNode) { $groupTitleNode.InnerText } else { $ruleTitle }

        $descNode = $rule.SelectSingleNode("*[local-name()='description']")
        $descRaw = if ($descNode) { $descNode.InnerText } else { "" }
        $discMatch = [regex]::Match($descRaw, '<VulnDiscussion>(.*?)</VulnDiscussion>', 'Singleline')
        $discussion = if ($discMatch.Success) { $discMatch.Groups[1].Value.Trim() } else { $descRaw.Trim() }

        $fixNode = $rule.SelectSingleNode("*[local-name()='fixtext']")
        $fixText = if ($fixNode) { $fixNode.InnerText } else { "" }

        $checkContent = ""
        $checkHref = ""
        $checkNode = $rule.SelectSingleNode("*[local-name()='check']")
        if ($checkNode) {
            $ccNode = $checkNode.SelectSingleNode("*[local-name()='check-content']")
            if ($ccNode) { $checkContent = $ccNode.InnerText }
            $refNode = $checkNode.SelectSingleNode("*[local-name()='check-content-ref']")
            if ($refNode) { $checkHref = $refNode.GetAttribute("href") }
        }

        $ccis = @()
        foreach ($id in $rule.SelectNodes("*[local-name()='ident']")) { $ccis += $id.InnerText }
        if ($ccis.Count -eq 0) { $ccis = @("CCI-000366") }

        $rules += [pscustomobject]@{
            GroupId      = $g.GetAttribute("id")
            RuleIdSrc    = $ruleIdSrc
            RuleId       = $ruleId
            RuleVersion  = $ruleVersion
            Title        = $ruleTitle
            Severity     = $severity
            GroupTitle   = $groupTitle
            Discussion   = $discussion
            CheckContent = $checkContent
            CheckHref    = $checkHref
            FixText      = $fixText
            Ccis         = $ccis
        }
    }

    $stigObj = [pscustomobject]@{
        StigId      = $stigId
        StigName    = $title
        DisplayName = $displayName
        ReleaseInfo = $releaseInfo
        Version     = $version
        Rules       = $rules
    }
    $script:stigCache[$FileName] = $stigObj
    return $stigObj
}

# ===========================================================================
# Rule / stig / cklb builders
# ===========================================================================

function New-RuleJson {
    param(
        [pscustomobject]$RuleDef, [string]$Status, [string]$TechName,
        [string]$ModuleName, [string]$ModuleVersion
    )

    $findingDetails = ""
    $comments = ""
    switch ($Status) {
        "open" {
            $findingDetails = "Evaluate-STIG $ModuleVersion ($ModuleName) found this to be OPEN on $scanDate`r`nResultHash: $(New-Hash)`r`n~~~~~`r`nRequired configuration for '$($RuleDef.Title)' was not present or did not match the expected value on $TechName."
        }
        "notafinding" {
            $findingDetails = "Evaluate-STIG $ModuleVersion ($ModuleName) found this to be NotAFinding on $scanDate`r`nResultHash: $(New-Hash)`r`n~~~~~`r`nConfiguration for '$($RuleDef.Title)' matches the expected value on $TechName."
        }
        "not_applicable" {
            $findingDetails = "Evaluate-STIG $ModuleVersion ($ModuleName) marked this Not_Applicable on $scanDate`r`nResultHash: $(New-Hash)`r`n~~~~~`r`nThe feature/role addressed by '$($RuleDef.Title)' is not present or not in use on this $TechName."
            $comments = "Not applicable - capability not installed/enabled on this asset."
        }
        default {
            $findingDetails = ""
        }
    }

    [ordered]@{
        group_id_src               = $RuleDef.GroupId
        group_tree                 = @(@{ id = $RuleDef.GroupId; title = $RuleDef.GroupTitle; description = "<GroupDescription></GroupDescription>" })
        group_id                   = $RuleDef.GroupId
        severity                   = $RuleDef.Severity
        group_title                = $RuleDef.GroupTitle
        rule_id_src                = $RuleDef.RuleIdSrc
        rule_id                    = $RuleDef.RuleId
        rule_version               = $RuleDef.RuleVersion
        rule_title                 = $RuleDef.Title
        fix_text                   = $RuleDef.FixText
        weight                     = "10.0"
        check_content              = $RuleDef.CheckContent
        check_content_ref          = [ordered]@{ href = $RuleDef.CheckHref; name = "M" }
        classification              = "UNCLASSIFIED"
        discussion                 = $RuleDef.Discussion
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
        ccis                        = $RuleDef.Ccis
        reference_identifier        = "$(Get-Random -Minimum 1000 -Maximum 9999)"
        uuid                        = [guid]::NewGuid().ToString()
        stig_uuid                   = $script:currentStigUuid
        status                      = $Status
        overrides                   = [ordered]@{}
        comments                    = $comments
        finding_details             = $findingDetails
    }
}

# Probability tuning for the compliance-weight model:
#   - Not_Applicable is assigned a flat share regardless of host maturity
#     (whether a control applies is a property of the box, not of how well
#     it's run).
#   - Not_Reviewed grows as ComplianceWeight shrinks - less mature hosts also
#     tend to have a bigger scan/review backlog, not just more open findings.
#   - Whatever's left splits Open vs NotAFinding using ComplianceWeight,
#     nudged per-rule by severity so CAT I items lag CAT III even on
#     otherwise well-managed hosts.
$script:NA_PROB = 0.09
function Get-NotReviewedProb([double]$w) { return 0.04 + (1 - $w) * 0.10 }
function Get-SeverityFactor([string]$sev) {
    switch ($sev) {
        "high" { return 0.85 }
        "low"  { return 1.10 }
        default { return 1.00 }
    }
}

function New-StigForHost {
    param([hashtable]$Profile, [string]$SeedKey, [double]$ComplianceWeight)

    $stig = Get-XccdfStig -FileName $Profile.File
    $rnd = New-Object System.Random((Get-StableHash $SeedKey))
    $nrProb = Get-NotReviewedProb $ComplianceWeight

    $script:currentStigUuid = [guid]::NewGuid().ToString()
    $rules = @()
    foreach ($rd in $stig.Rules) {
        $r = $rnd.NextDouble()
        if ($r -lt $script:NA_PROB) {
            $status = "not_applicable"
        }
        elseif ($r -lt ($script:NA_PROB + $nrProb)) {
            $status = "not_reviewed"
        }
        else {
            $sevFactor = Get-SeverityFactor $rd.Severity
            $effective = [Math]::Max(0.03, [Math]::Min(0.985, $ComplianceWeight * $sevFactor))
            $status = if ($rnd.NextDouble() -lt $effective) { "notafinding" } else { "open" }
        }
        $rules += New-RuleJson -RuleDef $rd -Status $status -TechName $Profile.TechName `
            -ModuleName $Profile.ModuleName -ModuleVersion "1.2604.2"
    }

    [ordered]@{
        "evaluate-stig"       = [ordered]@{
            time   = $scanTimeBase.ToString("yyyy-MM-ddTHH:mm:ss.fffffffzzz")
            module = [ordered]@{ name = $Profile.ModuleName; version = "1.2604.2" }
        }
        stig_name             = $stig.StigName
        display_name          = $stig.DisplayName
        stig_id               = $stig.StigId
        release_info          = $stig.ReleaseInfo
        version               = $stig.Version
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

function New-Asset {
    param(
        [string]$FileName, [string]$HostName, [string]$IpAddress, [string]$MacAddress, [string]$Fqdn,
        [string]$Role, [string]$TechArea = "None", [bool]$IsWebDb = $false,
        [array]$ProfileList, [double]$ComplianceWeight = 0.6
    )
    $stigs = @()
    foreach ($p in $ProfileList) {
        $stigs += New-StigForHost -Profile $p -SeedKey "$HostName|$($p.File)" -ComplianceWeight $ComplianceWeight
    }
    New-CklbFile -FileName $FileName -HostName $HostName -IpAddress $IpAddress -MacAddress $MacAddress -Fqdn $Fqdn `
        -Role $Role -TechArea $TechArea -IsWebDb $IsWebDb -Stigs $stigs
}

# ===========================================================================
# STIG profiles: just a source file + narrative TechName + module name.
# Everything else (title, id, version, release info, every rule/CCI/fix/
# check/discussion) is parsed straight out of the real XCCDF file.
# ===========================================================================

function New-Profile([string]$File, [string]$TechName, [string]$ModuleName) {
    return @{ File = $File; TechName = $TechName; ModuleName = $ModuleName }
}

$winserver2022 = New-Profile "U_MS_Windows_Server_2022_STIG_V2R8_Manual-xccdf.xml" `
    "the Windows Server 2022 host" "Scan-WindowsServer2022_Checks"
$addsstig = New-Profile "U_Active_Directory_Domain_STIG_V3R7_Manual-xccdf.xml" `
    "Active Directory Domain Services" "Scan-ADDomainServices_Checks"
$winserver2019 = New-Profile "U_MS_Windows_Server_2019_STIG_V3R8_Manual-xccdf.xml" `
    "the Windows Server 2019 host" "Scan-WindowsServer2019_Checks"
$mssql2016instance = New-Profile "U_MS_SQL_Server_2016_Instance_STIG_V3R6_Manual-xccdf.xml" `
    "the SQL Server instance" "Scan-MSSQLServer2016Instance_Checks"
$rhel9 = New-Profile "U_RHEL_9_STIG_V2R8_Manual-xccdf.xml" `
    "the RHEL 9 host" "Scan-RHEL9_Checks"
$apachetomcat9 = New-Profile "U_Apache_Tomcat_Application_Server_9_STIG_V3R4_Manual-xccdf.xml" `
    "the Apache Tomcat server" "Scan-ApacheTomcat9_Checks"
$ciscortrndm = New-Profile "U_Cisco_IOS_Router_NDM_STIG_V3R7_Manual-xccdf.xml" `
    "the Cisco IOS router" "Scan-CiscoIOSRouterNDM_Checks"
$ciscortrrtr = New-Profile "U_Cisco_IOS_Router_RTR_STIG_V3R4_Manual-xccdf.xml" `
    "the Cisco IOS router" "Scan-CiscoIOSRouterRTR_Checks"
$win11 = New-Profile "U_MS_Windows_11_STIG_V2R7_Manual-xccdf.xml" `
    "the Windows 11 workstation" "Scan-Windows11_Checks"
$office365 = New-Profile "U_MS_Office_365_ProPlus_STIG_V3R5_Manual-xccdf.xml" `
    "Microsoft Office 365 ProPlus" "Scan-Office365ProPlus_Checks"

# --- Additional profiles for a broader "small development network" batch ---
$addsforest = New-Profile "U_Active_Directory_Forest_STIG_V3R2_Manual-xccdf.xml" `
    "the Active Directory forest" "Scan-ADForest_Checks"
$win2012r2dc = New-Profile "U_MS_Windows_2012_and_2012_R2_DC_STIG_V3R7_Manual-xccdf.xml" `
    "the Windows Server 2012 R2 domain controller" "Scan-WindowsServer2012R2DC_Checks"
$win2012r2ms = New-Profile "U_MS_Windows_2012_and_2012_R2_MS_STIG_V3R7_Manual-xccdf.xml" `
    "the Windows Server 2012 R2 host" "Scan-WindowsServer2012R2MS_Checks"
$winsvr2016 = New-Profile "U_MS_Windows_Server_2016_STIG_V2R10_Manual-xccdf.xml" `
    "the Windows Server 2016 host" "Scan-WindowsServer2016_Checks"
$winsvr2025 = New-Profile "U_MS_Windows_Server_2025_STIG_V1R1_Manual-xccdf.xml" `
    "the Windows Server 2025 host" "Scan-WindowsServer2025_Checks"
$winsvrdns = New-Profile "U_MS_Windows_Server_DNS_STIG_V2R4_Manual-xccdf.xml" `
    "the Windows Server DNS role" "Scan-WindowsServerDNS_Checks"
$exch2019mbx = New-Profile "U_MS_Exchange_2019_Mailbox_Server_STIG_V2R3_Manual-xccdf.xml" `
    "the Exchange Mailbox server" "Scan-Exchange2019Mailbox_Checks"
$exch2019edge = New-Profile "U_MS_Exchange_2019_Edge_Server_STIG_V2R2_Manual-xccdf.xml" `
    "the Exchange Edge Transport server" "Scan-Exchange2019Edge_Checks"
$sharepoint13 = New-Profile "U_MS_Sharepoint_2013_STIG_V2R4_Manual-xccdf.xml" `
    "the SharePoint intranet site" "Scan-SharePoint2013_Checks"
$iis10server = New-Profile "U_MS_IIS_10-0_Server_STIG_V3R7_Manual-xccdf.xml" `
    "the IIS 10 web server" "Scan-IIS10Server_Checks"
$iis10site = New-Profile "U_MS_IIS_10-0_Site_STIG_V2R15_Manual-xccdf.xml" `
    "the IIS 10 web site" "Scan-IIS10Site_Checks"
$jboss63 = New-Profile "U_JBoss_EAP_6-3_STIG_V2R6_Manual-xccdf.xml" `
    "the JBoss EAP application server" "Scan-JBossEAP63_Checks"
$apache24uxsv = New-Profile "U_Apache_Server_2-4_UNIX_Server_STIG_V3R2_Manual-xccdf.xml" `
    "the Apache HTTP Server" "Scan-Apache24UnixServer_Checks"
$apache24uxst = New-Profile "U_Apache_Server_2-4_UNIX_Site_STIG_V2R6_Manual-xccdf.xml" `
    "the Apache HTTP Server site" "Scan-Apache24UnixSite_Checks"
$apache24wnsv = New-Profile "U_Apache_Server_2-4_Windows_Server_STIG_V3R4_Manual-xccdf.xml" `
    "the Apache HTTP Server" "Scan-Apache24WindowsServer_Checks"
$apache24wnst = New-Profile "U_Apache_Server_2-4_Windows_Site_STIG_V2R3_Manual-xccdf.xml" `
    "the Apache HTTP Server site" "Scan-Apache24WindowsSite_Checks"
$pgs9x = New-Profile "U_PGS_SQL_9-x_STIG_V2R5_Manual-xccdf.xml" `
    "the PostgreSQL database" "Scan-PostgreSQL9x_Checks"
$sql2022inst = New-Profile "U_MS_SQL_Server_2022_Instance_STIG_V1R4_Manual-xccdf.xml" `
    "the SQL Server instance" "Scan-MSSQLServer2022Instance_Checks"
$sql2022db = New-Profile "U_MS_SQL_Server_2022_Database_STIG_V1R3_Manual-xccdf.xml" `
    "the SQL Server database" "Scan-MSSQLServer2022Database_Checks"
$rke2 = New-Profile "U_RGS_RKE2_STIG_V2R6_Manual-xccdf.xml" `
    "the RKE2 Kubernetes node" "Scan-RKE2_Checks"
$jre8unix = New-Profile "U_Oracle_JRE_8_UNIX_STIG_V1R3_Manual-xccdf.xml" `
    "the Oracle JRE 8 runtime" "Scan-OracleJRE8Unix_Checks"
$amazonlinux23 = New-Profile "U_Amazon_Linux_2023_STIG_V1R3_Manual-xccdf.xml" `
    "the Amazon Linux 2023 host" "Scan-AmazonLinux2023_Checks"
$oel7 = New-Profile "U_Oracle_Linux_7_STIG_V3R5_Manual-xccdf.xml" `
    "the Oracle Linux 7 host" "Scan-OracleLinux7_Checks"
$oel8 = New-Profile "U_Oracle_Linux_8_STIG_V2R8_Manual-xccdf.xml" `
    "the Oracle Linux 8 host" "Scan-OracleLinux8_Checks"
$oel9 = New-Profile "U_Oracle_Linux_9_STIG_V1R5_Manual-xccdf.xml" `
    "the Oracle Linux 9 host" "Scan-OracleLinux9_Checks"
$ubuntu2404 = New-Profile "U_CAN_Ubuntu_24-04_LTS_STIG_V1R5_Manual-xccdf.xml" `
    "the Ubuntu 24.04 LTS host" "Scan-Ubuntu2404_Checks"
$ubuntu2204 = New-Profile "U_CAN_Ubuntu_22-04_LTS_STIG_V2R8_Manual-xccdf.xml" `
    "the Ubuntu 22.04 LTS host" "Scan-Ubuntu2204_Checks"
$ubuntu2004 = New-Profile "U_CAN_Ubuntu_20-04_LTS_STIG_V2R4_Manual-xccdf.xml" `
    "the Ubuntu 20.04 LTS host" "Scan-Ubuntu2004_Checks"
$ubuntu1804 = New-Profile "U_CAN_Ubuntu_18-04_LTS_STIG_V2R15_Manual-xccdf.xml" `
    "the Ubuntu 18.04 LTS host" "Scan-Ubuntu1804_Checks"
$ubuntu1604 = New-Profile "U_CAN_Ubuntu_16-04_LTS_STIG_V2R3_Manual-xccdf.xml.xml" `
    "the Ubuntu 16.04 LTS host" "Scan-Ubuntu1604_Checks"
$rhel7 = New-Profile "U_RHEL_7_STIG_V3R15_Manual-xccdf.xml" `
    "the RHEL 7 host" "Scan-RHEL7_Checks"
$rhel10 = New-Profile "U_RHEL_10_STIG_V1R1_Manual-xccdf.xml" `
    "the RHEL 10 host" "Scan-RHEL10_Checks"
$win10 = New-Profile "U_MS_Windows_10_STIG_V3R6_Manual-xccdf.xml" `
    "the Windows 10 workstation" "Scan-Windows10_Checks"
$win7 = New-Profile "U_MS_Windows_7_STIG_V1R32_Manual-xccdf.xml" `
    "the Windows 7 workstation" "Scan-Windows7_Checks"
$chrome = New-Profile "U_Google_Chrome_STIG_V2R11_Manual-xccdf.xml" `
    "the Google Chrome browser" "Scan-GoogleChrome_Checks"
$firefox = New-Profile "U_MOZ_Firefox_STIG_V6R7_Manual-xccdf.xml" `
    "the Mozilla Firefox browser" "Scan-MozillaFirefox_Checks"
$msedge = New-Profile "U_MS_Edge_V2R5_STIG_Manual-xccdf.xml" `
    "the Microsoft Edge browser" "Scan-MicrosoftEdge_Checks"
$ie11 = New-Profile "U_MS_IE11_STIG_V2R7_Manual-xccdf.xml" `
    "Internet Explorer 11" "Scan-IE11_Checks"
$defenderav = New-Profile "U_MS_Defender_Antivirus_STIG_V2R8_Manual-xccdf.xml" `
    "Microsoft Defender Antivirus" "Scan-DefenderAV_Checks"
$defenderfw = New-Profile "U_MS_Windows_Defender_Firewall_STIG_V2R2_Manual-xccdf.xml" `
    "Windows Defender Firewall" "Scan-DefenderFirewall_Checks"
$adobereader = New-Profile "U_Adobe_Acrobat_Reader_DC_Continuous_STIG_V2R1_Manual-xccdf.xml" `
    "Adobe Acrobat Reader DC" "Scan-AdobeAcrobatReaderDC_Checks"
$ciscoiosxertndm = New-Profile "U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml" `
    "the Cisco IOS-XE router" "Scan-CiscoIOSXERouterNDM_Checks"
$ciscoiosxertrtr = New-Profile "U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml" `
    "the Cisco IOS-XE router" "Scan-CiscoIOSXERouterRTR_Checks"
$ciscoiosxeswndm = New-Profile "U_Cisco_IOS-XE_Switch_NDM_STIG_V3R6_Manual-xccdf.xml" `
    "the Cisco IOS-XE switch" "Scan-CiscoIOSXESwitchNDM_Checks"
$ciscoiosxeswl2s = New-Profile "U_Cisco_IOS-XE_Switch_L2S_STIG_V3R2_Manual-xccdf.xml" `
    "the Cisco IOS-XE switch" "Scan-CiscoIOSXESwitchL2S_Checks"
$ciscoiosswndm = New-Profile "U_Cisco_IOS_Switch_NDM_STIG_V3R7_Manual-xccdf.xml" `
    "the Cisco IOS switch" "Scan-CiscoIOSSwitchNDM_Checks"
$ciscoiosswl2s = New-Profile "U_Cisco_IOS_Switch_L2S_STIG_V3R1_Manual-xccdf.xml" `
    "the Cisco IOS switch" "Scan-CiscoIOSSwitchL2S_Checks"
$horizonconn = New-Profile "U_VMW_Horizon_7-13_Connection_Server_STIG_V1R2_Manual-xccdf.xml" `
    "the Horizon Connection Server" "Scan-HorizonConnServer_Checks"
$horizonagent = New-Profile "U_VMW_Horizon_7-13_Agent_STIG_V1R1_Manual-xccdf.xml" `
    "the Horizon Agent host" "Scan-HorizonAgent_Checks"
$citrixvad = New-Profile "U_Citrix_VAD_7-x_Workspace_App_STIG_V1R3_Manual-xccdf.xml" `
    "the Citrix Workspace App client" "Scan-CitrixVADWorkspaceApp_Checks"

# ===========================================================================
# Sample assets - a small spread of hosts across a range of ComplianceWeight
# values so compliance percentages land in meaningfully different bands
# instead of clustering together.
# ===========================================================================

New-Asset -FileName "dc06-win2022.cklb" -HostName "DC06-WIN2022" `
    -IpAddress (Next-Ip "10.10.0" 16) -MacAddress (Next-Mac) -Fqdn "dc06-win2022.utsec.mil" `
    -Role "Domain Controller" -TechArea "Directory Services" `
    -ProfileList @($winserver2022, $addsstig) -ComplianceWeight 0.90

New-Asset -FileName "db-sql07.cklb" -HostName "DB-SQL07" `
    -IpAddress (Next-Ip "10.20.2" 62) -MacAddress (Next-Mac) -Fqdn "db-sql07.utsec.mil" `
    -Role "Member Server" -TechArea "Database" -IsWebDb $true `
    -ProfileList @($winserver2019, $mssql2016instance) -ComplianceWeight 0.68

New-Asset -FileName "web03-rhel9.cklb" -HostName "WEB03-RHEL9" `
    -IpAddress (Next-Ip "10.20.4" 30) -MacAddress (Next-Mac) -Fqdn "web03-rhel9.utsec.mil" `
    -Role "Member Server" -TechArea "Web Server" -IsWebDb $true `
    -ProfileList @($rhel9, $apachetomcat9) -ComplianceWeight 0.52

New-Asset -FileName "rtr-branch-06.cklb" -HostName "RTR-BRANCH-06" `
    -IpAddress (Next-Ip "10.10.5" 6) -MacAddress (Next-Mac) -Fqdn "rtr-branch-06.utsec.mil" `
    -Role "None" -TechArea "Network" `
    -ProfileList @($ciscortrndm, $ciscortrrtr) -ComplianceWeight 0.35

New-Asset -FileName "wks-05006.cklb" -HostName "WKS-05006" `
    -IpAddress (Next-Ip "10.30.6" 207) -MacAddress (Next-Mac "00:1C:42") -Fqdn "wks-05006.utsec.mil" `
    -Role "Workstation" -TechArea "None" `
    -ProfileList @($win11, $office365) -ComplianceWeight 0.80

# --- Batch 2: 50 more devices for a small development network ---

New-Asset -FileName "dc07-win2019.cklb" -HostName "DC07-WIN2019" -IpAddress "10.10.0.20" -MacAddress (Next-Mac) -Fqdn "dc07-win2019.utsec.mil" -Role "Domain Controller" -TechArea "Directory Services" -ProfileList @($winserver2019,$addsstig,$addsforest) -ComplianceWeight 0.75
New-Asset -FileName "dc-legacy01.cklb" -HostName "DC-LEGACY01" -IpAddress "10.10.0.21" -MacAddress (Next-Mac) -Fqdn "dc-legacy01.utsec.mil" -Role "Domain Controller" -TechArea "Directory Services" -ProfileList @($win2012r2dc,$addsstig) -ComplianceWeight 0.22
New-Asset -FileName "fs01-win2022.cklb" -HostName "FS01-WIN2022" -IpAddress "10.10.1.10" -MacAddress (Next-Mac) -Fqdn "fs01-win2022.utsec.mil" -Role "Member Server" -TechArea "File Server" -ProfileList @($winserver2022) -ComplianceWeight 0.72
New-Asset -FileName "dns02-win2022.cklb" -HostName "DNS02-WIN2022" -IpAddress "10.10.1.11" -MacAddress (Next-Mac) -Fqdn "dns02-win2022.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($winserver2022,$winsvrdns) -ComplianceWeight 0.80
New-Asset -FileName "legacy-app01.cklb" -HostName "LEGACY-APP01" -IpAddress "10.10.1.12" -MacAddress (Next-Mac) -Fqdn "legacy-app01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($win2012r2ms) -ComplianceWeight 0.30
New-Asset -FileName "mail-ex03.cklb" -HostName "MAIL-EX03" -IpAddress "10.20.1.10" -MacAddress (Next-Mac) -Fqdn "mail-ex03.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($winserver2019,$exch2019mbx) -ComplianceWeight 0.60
New-Asset -FileName "mail-edge01.cklb" -HostName "MAIL-EDGE01" -IpAddress "10.20.1.11" -MacAddress (Next-Mac) -Fqdn "mail-edge01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($winserver2019,$exch2019edge) -ComplianceWeight 0.55
New-Asset -FileName "wiki-sp01.cklb" -HostName "WIKI-SP01" -IpAddress "10.20.1.12" -MacAddress (Next-Mac) -Fqdn "wiki-sp01.utsec.mil" -Role "Member Server" -TechArea "Web Server" -IsWebDb $true -ProfileList @($winserver2019,$sharepoint13) -ComplianceWeight 0.55
New-Asset -FileName "web-iis01.cklb" -HostName "WEB-IIS01" -IpAddress "10.20.4.40" -MacAddress (Next-Mac) -Fqdn "web-iis01.utsec.mil" -Role "Member Server" -TechArea "Web Server" -IsWebDb $true -ProfileList @($winserver2022,$iis10server,$iis10site) -ComplianceWeight 0.70
New-Asset -FileName "web-iis02.cklb" -HostName "WEB-IIS02" -IpAddress "10.20.4.41" -MacAddress (Next-Mac) -Fqdn "web-iis02.utsec.mil" -Role "Member Server" -TechArea "Web Server" -IsWebDb $true -ProfileList @($winserver2022,$iis10server,$iis10site) -ComplianceWeight 0.45
New-Asset -FileName "app-jboss01.cklb" -HostName "APP-JBOSS01" -IpAddress "10.20.4.42" -MacAddress (Next-Mac) -Fqdn "app-jboss01.utsec.mil" -Role "Member Server" -TechArea "Web Server" -IsWebDb $true -ProfileList @($oel8,$jboss63) -ComplianceWeight 0.50
New-Asset -FileName "app-tomcat02.cklb" -HostName "APP-TOMCAT02" -IpAddress "10.20.4.43" -MacAddress (Next-Mac) -Fqdn "app-tomcat02.utsec.mil" -Role "Member Server" -TechArea "Web Server" -IsWebDb $true -ProfileList @($rhel9,$apachetomcat9) -ComplianceWeight 0.65
New-Asset -FileName "web-apache01.cklb" -HostName "WEB-APACHE01" -IpAddress "10.20.4.44" -MacAddress (Next-Mac) -Fqdn "web-apache01.utsec.mil" -Role "Member Server" -TechArea "Web Server" -IsWebDb $true -ProfileList @($oel8,$apache24uxsv,$apache24uxst) -ComplianceWeight 0.58
New-Asset -FileName "web-apache02win.cklb" -HostName "WEB-APACHE02WIN" -IpAddress "10.20.4.45" -MacAddress (Next-Mac) -Fqdn "web-apache02win.utsec.mil" -Role "Member Server" -TechArea "Web Server" -IsWebDb $true -ProfileList @($winserver2019,$apache24wnsv,$apache24wnst) -ComplianceWeight 0.42
New-Asset -FileName "db-pg02.cklb" -HostName "DB-PG02" -IpAddress "10.20.3.10" -MacAddress (Next-Mac) -Fqdn "db-pg02.utsec.mil" -Role "Member Server" -TechArea "Database" -IsWebDb $true -ProfileList @($rhel9,$pgs9x) -ComplianceWeight 0.66
New-Asset -FileName "db-pg03.cklb" -HostName "DB-PG03" -IpAddress "10.20.3.11" -MacAddress (Next-Mac) -Fqdn "db-pg03.utsec.mil" -Role "Member Server" -TechArea "Database" -IsWebDb $true -ProfileList @($ubuntu2204,$pgs9x) -ComplianceWeight 0.38
New-Asset -FileName "db-sql08.cklb" -HostName "DB-SQL08" -IpAddress "10.20.2.70" -MacAddress (Next-Mac) -Fqdn "db-sql08.utsec.mil" -Role "Member Server" -TechArea "Database" -IsWebDb $true -ProfileList @($winserver2022,$sql2022inst,$sql2022db) -ComplianceWeight 0.85
New-Asset -FileName "k8s-node01.cklb" -HostName "K8S-NODE01" -IpAddress "10.20.5.10" -MacAddress (Next-Mac) -Fqdn "k8s-node01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($rhel9,$rke2) -ComplianceWeight 0.70
New-Asset -FileName "k8s-node02.cklb" -HostName "K8S-NODE02" -IpAddress "10.20.5.11" -MacAddress (Next-Mac) -Fqdn "k8s-node02.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($rhel9,$rke2) -ComplianceWeight 0.55
New-Asset -FileName "k8s-node03.cklb" -HostName "K8S-NODE03" -IpAddress "10.20.5.12" -MacAddress (Next-Mac) -Fqdn "k8s-node03.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($rhel9,$rke2) -ComplianceWeight 0.40
New-Asset -FileName "ci-build01.cklb" -HostName "CI-BUILD01" -IpAddress "10.20.6.10" -MacAddress (Next-Mac) -Fqdn "ci-build01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($ubuntu2204,$jre8unix) -ComplianceWeight 0.48
New-Asset -FileName "ci-build02.cklb" -HostName "CI-BUILD02" -IpAddress "10.20.6.11" -MacAddress (Next-Mac) -Fqdn "ci-build02.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($oel8,$jre8unix) -ComplianceWeight 0.33
New-Asset -FileName "cloud-app01.cklb" -HostName "CLOUD-APP01" -IpAddress "10.20.7.10" -MacAddress (Next-Mac) -Fqdn "cloud-app01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($amazonlinux23) -ComplianceWeight 0.62
New-Asset -FileName "cloud-app02.cklb" -HostName "CLOUD-APP02" -IpAddress "10.20.7.11" -MacAddress (Next-Mac) -Fqdn "cloud-app02.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($amazonlinux23) -ComplianceWeight 0.44
New-Asset -FileName "oel7-legacy01.cklb" -HostName "OEL7-LEGACY01" -IpAddress "10.20.8.10" -MacAddress (Next-Mac) -Fqdn "oel7-legacy01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($oel7) -ComplianceWeight 0.28
New-Asset -FileName "oel8-svc01.cklb" -HostName "OEL8-SVC01" -IpAddress "10.20.8.11" -MacAddress (Next-Mac) -Fqdn "oel8-svc01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($oel8) -ComplianceWeight 0.58
New-Asset -FileName "oel9-svc02.cklb" -HostName "OEL9-SVC02" -IpAddress "10.20.8.12" -MacAddress (Next-Mac) -Fqdn "oel9-svc02.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($oel9) -ComplianceWeight 0.71
New-Asset -FileName "ubuntu2404-01.cklb" -HostName "UBUNTU2404-01" -IpAddress "10.20.9.10" -MacAddress (Next-Mac) -Fqdn "ubuntu2404-01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($ubuntu2404) -ComplianceWeight 0.88
New-Asset -FileName "ubuntu2004-01.cklb" -HostName "UBUNTU2004-01" -IpAddress "10.20.9.11" -MacAddress (Next-Mac) -Fqdn "ubuntu2004-01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($ubuntu2004) -ComplianceWeight 0.35
New-Asset -FileName "ubuntu1804-01.cklb" -HostName "UBUNTU1804-01" -IpAddress "10.20.9.12" -MacAddress (Next-Mac) -Fqdn "ubuntu1804-01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($ubuntu1804) -ComplianceWeight 0.20
New-Asset -FileName "ubuntu1604-01.cklb" -HostName "UBUNTU1604-01" -IpAddress "10.20.9.13" -MacAddress (Next-Mac) -Fqdn "ubuntu1604-01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($ubuntu1604) -ComplianceWeight 0.15
New-Asset -FileName "rhel7-legacy01.cklb" -HostName "RHEL7-LEGACY01" -IpAddress "10.20.10.10" -MacAddress (Next-Mac) -Fqdn "rhel7-legacy01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($rhel7) -ComplianceWeight 0.25
New-Asset -FileName "rhel10-new01.cklb" -HostName "RHEL10-NEW01" -IpAddress "10.20.10.11" -MacAddress (Next-Mac) -Fqdn "rhel10-new01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($rhel10) -ComplianceWeight 0.92
New-Asset -FileName "wks-win10-01.cklb" -HostName "WKS-WIN10-01" -IpAddress "10.30.6.10" -MacAddress (Next-Mac) -Fqdn "wks-win10-01.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win10,$office365,$chrome) -ComplianceWeight 0.70
New-Asset -FileName "wks-win10-02.cklb" -HostName "WKS-WIN10-02" -IpAddress "10.30.6.11" -MacAddress (Next-Mac) -Fqdn "wks-win10-02.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win10,$office365,$firefox) -ComplianceWeight 0.55
New-Asset -FileName "wks-win10-03.cklb" -HostName "WKS-WIN10-03" -IpAddress "10.30.6.12" -MacAddress (Next-Mac) -Fqdn "wks-win10-03.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win10,$msedge,$defenderav,$defenderfw) -ComplianceWeight 0.40
New-Asset -FileName "wks-win11-02.cklb" -HostName "WKS-WIN11-02" -IpAddress "10.30.6.13" -MacAddress (Next-Mac) -Fqdn "wks-win11-02.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win11,$office365,$chrome,$defenderav) -ComplianceWeight 0.85
New-Asset -FileName "wks-win11-03.cklb" -HostName "WKS-WIN11-03" -IpAddress "10.30.6.14" -MacAddress (Next-Mac) -Fqdn "wks-win11-03.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win11,$firefox,$msedge) -ComplianceWeight 0.75
New-Asset -FileName "wks-win11-04.cklb" -HostName "WKS-WIN11-04" -IpAddress "10.30.6.15" -MacAddress (Next-Mac) -Fqdn "wks-win11-04.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win11,$office365,$adobereader) -ComplianceWeight 0.60
New-Asset -FileName "legacy-win7-01.cklb" -HostName "LEGACY-WIN7-01" -IpAddress "10.30.7.10" -MacAddress (Next-Mac) -Fqdn "legacy-win7-01.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win7,$ie11) -ComplianceWeight 0.15
New-Asset -FileName "rtr-edge02.cklb" -HostName "RTR-EDGE02" -IpAddress "10.10.5.10" -MacAddress (Next-Mac) -Fqdn "rtr-edge02.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoiosxertndm,$ciscoiosxertrtr) -ComplianceWeight 0.80
New-Asset -FileName "rtr-branch07.cklb" -HostName "RTR-BRANCH07" -IpAddress "10.10.5.11" -MacAddress (Next-Mac) -Fqdn "rtr-branch07.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscortrndm,$ciscortrrtr) -ComplianceWeight 0.35
New-Asset -FileName "sw-core03.cklb" -HostName "SW-CORE03" -IpAddress "10.10.6.10" -MacAddress (Next-Mac) -Fqdn "sw-core03.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoiosxeswndm,$ciscoiosxeswl2s) -ComplianceWeight 0.75
New-Asset -FileName "sw-access22.cklb" -HostName "SW-ACCESS22" -IpAddress "10.10.6.11" -MacAddress (Next-Mac) -Fqdn "sw-access22.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoiosswndm,$ciscoiosswl2s) -ComplianceWeight 0.50
New-Asset -FileName "sw-access23.cklb" -HostName "SW-ACCESS23" -IpAddress "10.10.6.12" -MacAddress (Next-Mac) -Fqdn "sw-access23.utsec.mil" -Role "None" -TechArea "Network" -ProfileList @($ciscoiosswndm,$ciscoiosswl2s) -ComplianceWeight 0.30
New-Asset -FileName "horizon-conn01.cklb" -HostName "HORIZON-CONN01" -IpAddress "10.30.8.10" -MacAddress (Next-Mac) -Fqdn "horizon-conn01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($winserver2022,$horizonconn) -ComplianceWeight 0.65
New-Asset -FileName "horizon-agent01.cklb" -HostName "HORIZON-AGENT01" -IpAddress "10.30.8.11" -MacAddress (Next-Mac) -Fqdn "horizon-agent01.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win10,$horizonagent) -ComplianceWeight 0.55
New-Asset -FileName "citrix-wks01.cklb" -HostName "CITRIX-WKS01" -IpAddress "10.30.8.12" -MacAddress (Next-Mac) -Fqdn "citrix-wks01.utsec.mil" -Role "Workstation" -TechArea "None" -ProfileList @($win10,$citrixvad) -ComplianceWeight 0.60
New-Asset -FileName "winsvr2016-01.cklb" -HostName "WINSVR2016-01" -IpAddress "10.10.7.10" -MacAddress (Next-Mac) -Fqdn "winsvr2016-01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($winsvr2016) -ComplianceWeight 0.45
New-Asset -FileName "winsvr2025-01.cklb" -HostName "WINSVR2025-01" -IpAddress "10.10.7.11" -MacAddress (Next-Mac) -Fqdn "winsvr2025-01.utsec.mil" -Role "Member Server" -TechArea "None" -ProfileList @($winsvr2025) -ComplianceWeight 0.93

Write-Output "DONE"
