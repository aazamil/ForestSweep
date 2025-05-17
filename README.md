**ForestSweep** is a PowerShell-based toolkit for stealthy, low-footprint enumeration of Active Directory environments using raw LDAP queries via `.NET`. It avoids all dependencies on the ActiveDirectory module, ADSI, or external tools like AdFind or PowerView—making it highly portable, OPSEC-conscious, and effective for red, blue, and purple team assessments.

##  Key Features

- Uses only native .NET classes (`System.DirectoryServices.Protocols`)
- Enumerates users, computers, groups, GPOs, trusts, SPNs, domain controllers, and more
- Includes built-in OPSEC warnings for high-risk enumeration paths
- Supports obfuscation (attribute shuffling + filter encoding)
- Modular and extensible logic for easy customization
- No third-party dependencies; runs natively on any PowerShell 5+ system

##  Example Usage

```powershell
# Basic domain enumeration over LDAP (port 389)
.\ForestSweep.ps1 -Domain "corp.example.com"

# Use a specific Domain Controller with LDAPS (SSL on port 636)
.\ForestSweep.ps1 -Domain "corp.example.com" -LDAPServer "dc01.corp.example.com" -Port 636 -UseSSL

# Run enumeration with mild obfuscation (randomized attribute order + encoded LDAP filters)
.\ForestSweep.ps1 -Domain "corp.example.com" -Obfuscate

# Exclude verbose attributes like objectGUID from output
.\ForestSweep.ps1 -Domain "corp.local" -ExcludeAttributes objectGUID,whenCreated

# Enable detailed logs for script activity
.\ForestSweep.ps1 -Domain "corp.local" -VerboseOutput

```

##  Use Cases

- Red Team reconnaissance in domain environments (low noise, no artifacts)
- GPO + SPN mapping without triggering common EDR detections
- Purple Team workflows and training environments


## Requirements

- PowerShell 5.1 or newr
- Domain credentials with basic read access(non-privilaged)
- Network reachability to Domain Controller (LDAP:389 or LDAPS:636)
