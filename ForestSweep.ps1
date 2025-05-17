<#
.SYNOPSIS
Performs Active Directory domain enumeration using raw LDAP over PowerShell without relying on ADSI, ADModule, or external tools.

.DESCRIPTION
This script connects to an LDAP server using System.DirectoryServices.Protocols and enumerates key objects in an enterprise AD environment, including:
- Users
- Computers
- Groups
- GPOs
- Trusts
- Domain Controllers
- SPNs
- Admin group memberships
- Delegation settings

Supports modular, parameterized execution with OPSEC warning.

.PARAMETER Domain
Fully qualified domain name of the target environment (e.g., contoso.com). Mandatory.

.PARAMETER LDAPServer
FQDN or IP of the LDAP server. Defaults to the provided domain.

.PARAMETER Port
Port to use for LDAP communication (default: 389). Use 636 for SSL if -UseSSL is set.

.PARAMETER UseSSL
Switch to use LDAPS (SSL). Requires port 636 and a valid certificate on the server.

.PARAMETER Output
Output format. Valid values:
- console (default)
- csv (to be added)
- json (to be added)

.EXAMPLE
.\ForestSweep.ps1 -Domain "corp.example.com"
Performs default LDAP enumeration using domain as LDAP server on port 389.

.EXAMPLE
.\ForestSweep.ps1 -Domain "corp.example.com" -LDAPServer "dc01.corp.example.com" -Port 636 -UseSSL
Uses LDAPS over port 636 to enumerate domain via specific DC.

.EXAMPLE
.\ForestSweep.ps1 -Domain "corp.local" -Output "json"
Runs full enumeration and returns output in JSON format (future support placeholder).

.NOTES
- Credentials are prompted at runtime.
- OPSEC warning is displayed.
- Script uses only built-in .NET classes for LDAP enumeration.

.LINK
https://github.com/SilverKin9/ForestSweep
#>

# ForestSweep.ps1 - Domain Enumeration Toolkit (Raw LDAP)
# Author: @SilverKin9
# Purpose: Enumerate Active Directory over LDAP.

param(
    [Parameter(Mandatory=$false, HelpMessage="Enable basic obfuscation of LDAP filters and attributes")]
    [switch]$Obfuscate,
    [Parameter(Mandatory=$true, HelpMessage="Fully qualified domain name (e.g., contoso.com)")]
    [ValidatePattern("^[a-zA-Z0-9.-]+$")]
    [string]$Domain,

    [Parameter(Mandatory=$false, HelpMessage="LDAP server address (defaults to domain)")]
    [string]$LDAPServer = $Domain,

    [Parameter(Mandatory=$false, HelpMessage="LDAP port (389 or 636 for SSL)")]
    [ValidateRange(1,65535)]
    [int]$Port = 389,

    [Parameter(Mandatory=$false, HelpMessage="Use SSL for LDAP connection")]
    [switch]$UseSSL,

    [Parameter(Mandatory=$false, HelpMessage="Output format: console, csv, json")]
    [ValidateSet("console", "csv", "json")]
    [string]$Output = "console"
)

function Show-OPSECWarning {
    Write-Host "[!] WARNING: This script performs LDAP enumeration which could be detected in monitored environments." -ForegroundColor Yellow
    Write-Host "[!] Ensure you have authorization to conduct such enumeration." -ForegroundColor Yellow
}

Show-OPSECWarning

# Get credentials
$Credential = Get-Credential -Message "Enter domain credentials"

# Create LDAP connection
$identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LDAPServer, $Port, $false, $false)
$connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier, $Credential, [System.DirectoryServices.Protocols.AuthType]::Negotiate)
$connection.SessionOptions.Sealing = $true
$connection.SessionOptions.Signing = $true
if ($UseSSL) {
    $connection.SessionOptions.SecureSocketLayer = $true
}
$connection.Bind()

# Get base DN
$rootRequest = New-Object System.DirectoryServices.Protocols.SearchRequest("", "(objectClass=*)", "Base", @("defaultNamingContext", "configurationNamingContext", "schemaNamingContext"))
$rootResponse = $connection.SendRequest($rootRequest)
$baseDN = $rootResponse.Entries[0].Attributes["defaultNamingContext"][0]
$configDN = $rootResponse.Entries[0].Attributes["configurationNamingContext"][0]
$schemaDN = $rootResponse.Entries[0].Attributes["schemaNamingContext"][0]

function Invoke-LDAPQuery {
    function Decode-Filter {
        param ([string]$Encoded)
        return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Encoded))
    }

    function Shuffle-Array {
        param ([object[]]$Array)
        $shuffled = $Array.Clone()
        for ($i = $shuffled.Length - 1; $i -gt 0; $i--) {
            $j = Get-Random -Minimum 0 -Maximum ($i + 1)
            $temp = $shuffled[$i]
            $shuffled[$i] = $shuffled[$j]
            $shuffled[$j] = $temp
        }
        return $shuffled
    }
    param (
        [string]$SearchBase,
        [string]$LDAPFilter,
        [string[]]$Attributes
    )
    try {
        $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest($SearchBase, $LDAPFilter, "Subtree", $Attributes)
        $searchResponse = $connection.SendRequest($searchRequest)
        return $searchResponse.Entries
    } catch {
        Write-Warning "LDAP query failed: $_"
        return @()
    }
}

function Show-Entries {
    param($Entries)
    foreach ($entry in $Entries) {
        Write-Host "`n[+] $($entry.DistinguishedName)" -ForegroundColor Cyan
        foreach ($attr in $entry.Attributes.AttributeNames) {
            $values = $entry.Attributes[$attr]
            $valueList = @()
            foreach ($val in $values) {
                if ($val -is [byte[]]) {
                    $valueList += [System.BitConverter]::ToString($val)
                } else {
                    $valueList += $val.ToString()
                }
            }
            $joined = $valueList -join ", "
            Write-Host "$attr: $joined"
        }
    }
}

# Dispatcher for enumeration
$enumerationTasks = @(
    @{ Name = "Users"; Filter = "(&(objectCategory=person)(objectClass=user))"; Attributes = @("sAMAccountName", "displayName", "mail", "lastLogonTimestamp") },
    @{ Name = "Computers"; Filter = "(objectCategory=computer)"; Attributes = @("cn", "dNSHostName", "operatingSystem") },
    @{ Name = "Groups"; Filter = "(objectCategory=group)"; Attributes = @("cn", "member") },
    @{ Name = "GPOs"; Filter = "(objectClass=groupPolicyContainer)"; Base = "CN=Policies,CN=System,$baseDN"; Attributes = @("displayName", "gPCFileSysPath") },
    @{ Name = "Trusts"; Filter = "(objectClass=trustedDomain)"; Base = "CN=System,$baseDN"; Attributes = @("cn", "trustPartner", "trustDirection") },
    @{ Name = "Domain Controllers"; Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"; Attributes = @("cn", "dNSHostName") },
    @{ Name = "Unconstrained Delegation"; Filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"; Attributes = @("sAMAccountName") },
    @{ Name = "Kerberos SPNs"; Filter = "(&(objectClass=user)(servicePrincipalName=*))"; Attributes = @("sAMAccountName", "servicePrincipalName") }
)

foreach ($task in $enumerationTasks) {
    if ($task.Name -in @("Unconstrained Delegation", "Kerberos SPNs", "Trusts", "Admin Groups")) {
        Write-Host "[!] OPSEC Warning: Enumerating $($task.Name) may trigger security alerts in monitored environments." -ForegroundColor Yellow
    }
    $base = if ($task.Base) { $task.Base } else { $baseDN }
    Write-Host "[*] Enumerating $($task.Name)..."
    $ldapFilter = if ($Obfuscate) { Decode-Filter ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($task.Filter))) } else { $task.Filter }
    $attributes = if ($Obfuscate) { Shuffle-Array $task.Attributes } else { $task.Attributes }
    $entries = Invoke-LDAPQuery -SearchBase $base -LDAPFilter $ldapFilter -Attributes $attributes
    Show-Entries $entries
}

# Admin Groups
Write-Host "[*] Enumerating Admin Groups..."
$adminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
foreach ($group in $adminGroups) {
    $filter = "(&(objectClass=user)(memberOf=CN=$group,CN=Users,$baseDN))"
    $admins = Invoke-LDAPQuery -SearchBase $baseDN -LDAPFilter $filter -Attributes @("sAMAccountName")
    Write-Host "`n[+] Members of $group"
    Show-Entries $admins
}
