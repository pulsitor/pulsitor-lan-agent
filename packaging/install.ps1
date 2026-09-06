<#
.SYNOPSIS
    Installs the Pulsitor LAN agent as a Windows service.

.DESCRIPTION
    Downloads the agent from its GitHub releases, checks it against the published
    SHA-256 sums and hands over to its own `service install`, which redeems the
    enrollment token, registers the service and starts it. The service runs as
    LocalSystem, starts with the machine and restarts itself if it ever stops.

    The Pulsitor endpoint is compiled into the binary, so there is nothing to configure.

    Must be run from an elevated PowerShell prompt: registering a service is an
    administrator's privilege.

.EXAMPLE
    .\install.ps1 -EnrollToken abc123

.EXAMPLE
    .\install.ps1 -Binary .\pulsitor-lan-agent-windows-amd64.exe -EnrollToken abc123

.EXAMPLE
    .\install.ps1 -EnrollToken abc123 -Version v1.2.3
#>

[CmdletBinding()]
param(
    [string] $EnrollToken,
    [string] $EnrollFile,
    [string] $Repository = $(if ($env:PULSITOR_REPO) { $env:PULSITOR_REPO } else { 'pulsitor/pulsitor-lan-agent' }),
    [string] $Version = $(if ($env:PULSITOR_VERSION) { $env:PULSITOR_VERSION } else { 'latest' }),
    # Development override only; the release endpoint is compiled into the binary.
    [string] $Server,
    [string] $Binary,
    [string] $State,
    [string] $LogFile,
    [switch] $VerboseLogging
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Fail([string] $message) {
    # Write-Error under $ErrorActionPreference = 'Stop' raises a terminating error and
    # buries the message in a stack trace, which is not what the operator needs to read.
    Write-Host "install: $message" -ForegroundColor Red
    exit 1
}

# Registering a service needs administrator rights, and finding that out after the
# download is a worse experience than finding it out now.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'installing a service needs administrator rights; re-run from an elevated PowerShell prompt'
}

# The architecture of the operating system, not of the PowerShell host: a 32 bit
# PowerShell on 64 bit Windows would otherwise install the wrong binary.
switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $architecture = 'amd64' }
    'ARM64' { $architecture = 'arm64' }
    'x86'   { $architecture = if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') { 'amd64' } else { '386' } }
    default { Fail "$($env:PROCESSOR_ARCHITECTURE) is not a published architecture" }
}

$workspace = $null

try {
    if (-not $Binary) {
        $name = "pulsitor-lan-agent-windows-$architecture.exe"
        $workspace = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Path $workspace | Out-Null

        # Windows PowerShell 5.1 negotiates TLS 1.0 by default, which a current server
        # will refuse outright.
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # GitHub serves "releases/latest/download/<asset>" as a redirect to the newest
        # release, so "latest" needs no API call and no token — which also keeps this
        # working on a machine where the API is blocked but the CDN is not.
        $base = if ($Version -eq 'latest') {
            "https://github.com/$Repository/releases/latest/download"
        } else {
            "https://github.com/$Repository/releases/download/$Version"
        }

        $Binary = Join-Path $workspace $name
        $sums = Join-Path $workspace 'SHA256SUMS'

        Write-Host "downloading $name ($Version)"

        # The progress bar makes Invoke-WebRequest an order of magnitude slower on
        # Windows PowerShell, and nobody reads it in an install script.
        $previousProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try {
            Invoke-WebRequest -Uri "$base/$name" -OutFile $Binary -UseBasicParsing
            Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sums -UseBasicParsing
        } finally {
            $ProgressPreference = $previousProgress
        }

        # This script runs as an administrator and what it downloads is then registered
        # as a LocalSystem service, so an unverified artefact is a free SYSTEM shell
        # for whoever can answer the request.
        $expected = $null
        foreach ($line in Get-Content $sums) {
            $fields = $line -split '\s+\*?', 2
            if ($fields.Count -eq 2 -and $fields[1].Trim() -eq $name) {
                $expected = $fields[0].Trim().ToLowerInvariant()
                break
            }
        }

        if (-not $expected) {
            Fail "$name is not listed in SHA256SUMS"
        }

        $actual = (Get-FileHash -Path $Binary -Algorithm SHA256).Hash.ToLowerInvariant()

        if ($actual -ne $expected) {
            Fail "checksum mismatch for ${name}: got $actual, expected $expected"
        }

        # A file downloaded through a browser or WebRequest carries a zone marker that
        # makes Windows refuse to execute it without a prompt nobody is there to answer.
        Unblock-File -Path $Binary -ErrorAction SilentlyContinue
    }
    elseif (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
        Fail "$Binary does not exist"
    }

    $arguments = @('service', 'install')

    if ($Server)      { $arguments += @('--server', $Server) }
    if ($EnrollToken) { $arguments += @('--enroll', $EnrollToken) }
    if ($EnrollFile)  { $arguments += @('--enroll-file', $EnrollFile) }
    if ($State)       { $arguments += @('--state', $State) }
    if ($LogFile)     { $arguments += @('--log-file', $LogFile) }
    if ($VerboseLogging) { $arguments += '--verbose' }

    & $Binary @arguments

    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    Write-Host ''
    Write-Host 'pulsitor-lan-agent service status     # what it is doing'
    Write-Host 'pulsitor-lan-agent service uninstall  # to remove it'
}
finally {
    if ($workspace -and (Test-Path -LiteralPath $workspace)) {
        Remove-Item -Recurse -Force -LiteralPath $workspace -ErrorAction SilentlyContinue
    }
}
