#!/usr/bin/env pwsh
<#
.SYNOPSIS
Download and install azd on the local machine.

.DESCRIPTION
Downloads and installs azd on the local machine. Includes ability to configure
download and install locations.

.PARAMETER BaseUrl
Specifies the base URL to use when downloading. Default is
https://azdrelease.azureedge.net/azd/standalone

.PARAMETER Version
Specifies the version to use. Default is `latest`. Valid values include a
SemVer version number (e.g. 1.0.0 or 1.1.0-beta.1), `latest`, `daily`

.PARAMETER DryRun
Print the download URL and quit. Does not download or install.

.PARAMETER InstallFolder
Location to install azd.

.PARAMETER SymlinkFolder
(Mac/Linux only) Folder to symlink 

.PARAMETER DownloadTimeoutSeconds
Download timeout in seconds. Default is 120 (2 minutes).

.PARAMETER SkipVerify
Skips verification of the downloaded file.

.PARAMETER InstallShScriptUrl
(Mac/Linux only) URL to the install-azd.sh script. Default is https://aka.ms/install-azd.sh

.EXAMPLE
powershell -ex AllSigned -c "Invoke-RestMethod 'https://aka.ms/install-azd.ps1' | Invoke-Expression"

Install the azd CLI from a Windows shell

The use of `-ex AllSigned` is intended to handle the scenario where a machine's
default execution policy is restricted such that modules used by
`install-azd.ps1` cannot be loaded. Because this syntax is piping output from
`Invoke-RestMethod` to `Invoke-Expression` there is no direct valication of the
`install-azd.ps1` script's signature. Validation of the script can be
accomplished by downloading the script to a file and executing the script file.

.EXAMPLE
Invoke-RestMethod 'https://aka.ms/install-azd.ps1' -OutFile 'install-azd.ps1'
PS > ./install-azd.ps1

Download the installer and execute from PowerShell

.EXAMPLE
Invoke-RestMethod 'https://aka.ms/install-azd.ps1' -OutFile 'install-azd.ps1'
PS > ./install-azd.ps1 -Version daily

Download the installer and install the "daily" build
#>

param(
    [string] $BaseUrl = "https://azdrelease.azureedge.net/azd/standalone/release",
    [string] $Version = "stable",
    [switch] $DryRun,
    [string] $InstallFolder,
    [string] $SymlinkFolder,
    [switch] $SkipVerify,
    [int] $DownloadTimeoutSeconds = 120,
    [switch] $NoTelemetry,
    [string] $InstallShScriptUrl = "https://aka.ms/install-azd.sh"
)

function isLinuxOrMac {
    return $IsLinux -or $IsMacOS
}

# Does some very basic parsing of /etc/os-release to output the value present in
# the file. Since only lines that start with '#' are to be treated as comments
# according to `man os-release` there is no additional parsing of comments
# Options like:
# bash -c "set -o allexport; source /etc/os-release;set +o allexport; echo $VERSION_ID"
# were considered but it's possible that bash is not installed on the system and
# these commands would not be available.
function getOsReleaseValue($key) {
    $value = $null
    foreach ($line in Get-Content '/etc/os-release') {
        if ($line -like "$key=*") {
            # 'ID="value" -> @('ID', '"value"')
            $splitLine = $line.Split('=', 2)

            # Remove surrounding whitespaces and quotes
            # ` "value" ` -> `value`
            # `'value'` -> `value`
            $value = $splitLine[1].Trim().Trim(@("`"", "'"))
        }
    }
    return $value
}

function getOs {
    $os = [Environment]::OSVersion.Platform.ToString()
    try {
        if (isLinuxOrMac) {
            if ($IsLinux) {
                $os = getOsReleaseValue 'ID'
            } elseif ($IsMacOs) {
                $os = sw_vers -productName
            }
        }
    } catch {
        Write-Error "Error getting OS name $_"
        $os = "error"
    }
    return $os
}

function getOsVersion {
    $version = [Environment]::OSVersion.Version.ToString()
    try {
        if (isLinuxOrMac) {
            if ($IsLinux) {
                $version = getOsReleaseValue 'VERSION_ID'
            } elseif ($IsMacOS) {
                $version = sw_vers -productVersion
            }
        }
    } catch {
        Write-Error "Error getting OS version $_"
        $version = "error"
    }
    return $version
}

function isWsl {
    $isWsl = $false
    if ($IsLinux) {
        $kernelRelease = uname --kernel-release
        if ($kernelRelease -like '*wsl*') {
            $isWsl = $true
        }
    }
    return $isWsl
}

function getTerminal {
    return (Get-Process -Id $PID).ProcessName
}

function getExecutionEnvironment {
    $executionEnvironment = 'Desktop'
    if ($env:GITHUB_ACTIONS) {
        $executionEnvironment = 'GitHub Actions'
    } elseif ($env:SYSTEM_TEAMPROJECTID) {
        $executionEnvironment = 'Azure DevOps'
    }
    return $executionEnvironment
}

function promptForTelemetry {
    # UserInteractive may return $false if the session is not interactive
    # but this does not work in 100% of cases. For example, running:
    # "powershell -NonInteractive -c '[Environment]::UserInteractive'"
    # results in output of "True" even though the shell is not interactive.
    if (![Environment]::UserInteractive) {
        return $false
    }

    Write-Host "Answering 'yes' below will send data to Microsoft. To learn more about data collection see:"
    Write-Host "https://go.microsoft.com/fwlink/?LinkId=521839"
    Write-Host ""
    Write-Host "You can also file an issue at https://github.com/Azure/azure-dev/issues/new?assignees=&labels=&template=issue_report.md&title=%5BIssue%5D"

    try {
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription `
            "&Yes", `
            "Sends failure report to Microsoft"
        $no = New-Object System.Management.Automation.Host.ChoiceDescription `
            "&No", `
            "Exits the script without sending a failure report to Microsoft (Default)"
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $decision = $Host.UI.PromptForChoice( `
            'Confirm issue report', `
            'Do you want to send diagnostic data about the failure to Microsoft?', `
            $options, `
            1 `                     # Default is 'No'
        )

        # Return $true if user consents
        return $decision -eq 0
    } catch {
        # Failure to prompt generally indicates that the environment is not
        # interactive and the default resposne can be assumed.
        return $false
    }
}

function reportTelemetryIfEnabled($eventName, $reason='', $additionalProperties = @{}) {
    if ($NoTelemetry -or $env:AZURE_DEV_COLLECT_TELEMETRY -eq 'no') {
        Write-Verbose "Telemetry disabled. No telemetry reported." -Verbose:$Verbose
        return
    }

    $IKEY = 'a9e6fa10-a9ac-4525-8388-22d39336ecc2'

    $telemetryObject = @{
        iKey = $IKEY;
        name = "Microsoft.ApplicationInsights.$($IKEY.Replace('-', '')).Event";
        time = (Get-Date).ToUniversalTime().ToString('o');
        data = @{
            baseType = 'EventData';
            baseData = @{
                ver = 2;
                name = $eventName;
                properties = @{
                    installVersion = $Version;
                    reason = $reason;
                    os = getOs;
                    osVersion = getOsVersion;
                    isWsl = isWsl;
                    terminal = getTerminal;
                    executionEnvironment = getExecutionEnvironment;
                };
            }
        }
    }

    # Add entries from $additionalProperties. These may overwrite existing
    # entries in the properties field.
    if ($additionalProperties -and $additionalProperties.Count) {
        foreach ($entry in $additionalProperties.GetEnumerator()) {
            $telemetryObject.data.baseData.properties[$entry.Name] = $entry.Value
        }
    }

    Write-Host "An error was encountered during install: $reason"
    Write-Host "Error data collected:"
    $telemetryDataTable = $telemetryObject.data.baseData.properties | Format-Table | Out-String
    Write-Host $telemetryDataTable
    if (!(promptForTelemetry)) {
        # The user responded 'no' to the telemetry prompt or is in a
        # non-interactive session. Do not send telemetry.
        return
    }

    try {
        Invoke-RestMethod `
            -Uri 'https://centralus-2.in.applicationinsights.azure.com/v2/track' `
            -ContentType 'application/json' `
            -Method Post `
            -Body (ConvertTo-Json -InputObject $telemetryObject -Depth 100 -Compress) | Out-Null
        Write-Verbose -Verbose:$Verbose "Telemetry posted"
    } catch {
        Write-Host $_
        Write-Verbose -Verbose:$Verbose "Telemetry post failed"
    }
}

if (isLinuxOrMac) {
    if (!(Get-Command curl)) { 
        Write-Error "Command could not be found: curl."
        exit 1
    }
    if (!(Get-Command bash)) { 
        Write-Error "Command could not be found: bash."
        exit 1
    }

    $params = @(
        '--base-url', "'$BaseUrl'", 
        '--version', "'$Version'"
    )

    if ($InstallFolder) {
        $params += '--install-folder', "'$InstallFolder'"
    }

    if ($SymlinkFolder) {
        $params += '--symlink-folder', "'$SymlinkFolder'"
    }

    if ($SkipVerify) { 
        $params += '--skip-verify'
    }

    if ($DryRun) {
        $params += '--dry-run'
    }

    if ($NoTelemetry) {
        $params += '--no-telemetry'
    }

    if ($VerbosePreference -eq 'Continue') {
        $params += '--verbose'
    }

    $bashParameters = $params -join ' '
    Write-Verbose "Running: curl -fsSL $InstallShScriptUrl | bash -s -- $bashParameters" -Verbose:$Verbose
    bash -c "curl -fsSL $InstallShScriptUrl | bash -s -- $bashParameters"
    exit $LASTEXITCODE
}

try {
    $packageFilename = "azd-windows-amd64.msi"

    $downloadUrl = "$BaseUrl/$packageFilename"
    if ($Version) {
        $downloadUrl = "$BaseUrl/$Version/$packageFilename"
    }

    if ($DryRun) {
        Write-Host $downloadUrl
        exit 0
    }

    $tempFolder = "$([System.IO.Path]::GetTempPath())$([System.IO.Path]::GetRandomFileName())"
    Write-Verbose "Creating temporary folder for downloading package: $tempFolder"
    New-Item -ItemType Directory -Path $tempFolder | Out-Null

    Write-Verbose "Downloading build from $downloadUrl" -Verbose:$Verbose
    $releaseArtifactFilename = Join-Path $tempFolder $packageFilename
    try {
        $global:LASTEXITCODE = 0
        Invoke-WebRequest -Uri $downloadUrl -OutFile $releaseArtifactFilename -TimeoutSec $DownloadTimeoutSeconds
        if ($LASTEXITCODE) {
            throw "Invoke-WebRequest failed with nonzero exit code: $LASTEXITCODE"
        }
    } catch {
        Write-Error -ErrorRecord $_
        reportTelemetryIfEnabled 'InstallFailed' 'DownloadFailed' @{ downloadUrl = $downloadUrl }
        exit 1
    }
   

    try {
        if (!$SkipVerify) {
            try {
                Write-Verbose "Verifying signature of $releaseArtifactFilename" -Verbose:$Verbose
                $signature = Get-AuthenticodeSignature $releaseArtifactFilename
                if ($signature.Status -ne 'Valid') {
                    Write-Error "Signature of $releaseArtifactFilename is not valid"
                    reportTelemetryIfEnabled 'InstallFailed' 'SignatureVerificationFailed'
                    exit 1
                }
            } catch {
                Write-Error -ErrorRecord $_
                reportTelemetryIfEnabled 'InstallFailed' 'SignatureVerificationFailed'
                exit 1
            }
        }

        Write-Verbose "Installing MSI" -Verbose:$Verbose
        $MSIEXEC = "${env:SystemRoot}\System32\msiexec.exe"
        $installProcess = Start-Process $MSIEXEC `
            -ArgumentList @("/i", "`"$releaseArtifactFilename`"", "/qn", "INSTALLDIR=`"$InstallFolder`"", "INSTALLEDBY=`"install-azd.ps1`"") `
            -PassThru `
            -Wait

        if ($installProcess.ExitCode) {
            if ($installProcess.ExitCode -eq 1603) {
                Write-Host "A later version of Azure Developer CLI may already be installed. Use 'Add or remove programs' to uninstall that version and try again."
            }

            Write-Error "Could not install MSI at $releaseArtifactFilename. msiexec.exe returned exit code: $($installProcess.ExitCode)"

            reportTelemetryIfEnabled 'InstallFailed' 'MsiFailure' @{ msiExitCode = $installProcess.ExitCode }
            exit 1
        }
    } catch {
        Write-Error -ErrorRecord $_
        reportTelemetryIfEnabled 'InstallFailed' 'GeneralInstallFailure'
        exit 1
    }

    Write-Verbose "Cleaning temporary install directory: $tempFolder" -Verbose:$Verbose
    Remove-Item $tempFolder -Recurse -Force | Out-Null

    if (!(isLinuxOrMac)) {
        # Installed on Windows
        Write-Host "Successfully installed azd"
        Write-Host "Azure Developer CLI (azd) installed successfully. You may need to restart running programs for installation to take effect."
        Write-Host "- For Windows Terminal, start a new Windows Terminal instance."
        Write-Host "- For VSCode, close all instances of VSCode and then restart it."
    }
    Write-Host ""
    Write-Host "The Azure Developer CLI collects usage data and sends that usage data to Microsoft in order to help us improve your experience."
    Write-Host "You can opt-out of telemetry by setting the AZURE_DEV_COLLECT_TELEMETRY environment variable to 'no' in the shell you use."
    Write-Host ""
    Write-Host "Read more about Azure Developer CLI telemetry: https://github.com/Azure/azure-dev#data-collection"

    exit 0
} catch {
    Write-Error -ErrorRecord $_
    reportTelemetryIfEnabled 'InstallFailed' 'UnhandledError' @{ exceptionName = $_.Exception.GetType().Name; }
    exit 1
}
# SIG # Begin signature block
# MIInvgYJKoZIhvcNAQcCoIInrzCCJ6sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA10yLZ3axwWDzM
# J/4MWPpF5V4v/sfKMnW3fnePgxrRDKCCDXYwggX0MIID3KADAgECAhMzAAADrzBA
# DkyjTQVBAAAAAAOvMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMxMTE2MTkwOTAwWhcNMjQxMTE0MTkwOTAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOS8s1ra6f0YGtg0OhEaQa/t3Q+q1MEHhWJhqQVuO5amYXQpy8MDPNoJYk+FWA
# hePP5LxwcSge5aen+f5Q6WNPd6EDxGzotvVpNi5ve0H97S3F7C/axDfKxyNh21MG
# 0W8Sb0vxi/vorcLHOL9i+t2D6yvvDzLlEefUCbQV/zGCBjXGlYJcUj6RAzXyeNAN
# xSpKXAGd7Fh+ocGHPPphcD9LQTOJgG7Y7aYztHqBLJiQQ4eAgZNU4ac6+8LnEGAL
# go1ydC5BJEuJQjYKbNTy959HrKSu7LO3Ws0w8jw6pYdC1IMpdTkk2puTgY2PDNzB
# tLM4evG7FYer3WX+8t1UMYNTAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQURxxxNPIEPGSO8kqz+bgCAQWGXsEw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMTgyNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAISxFt/zR2frTFPB45Yd
# mhZpB2nNJoOoi+qlgcTlnO4QwlYN1w/vYwbDy/oFJolD5r6FMJd0RGcgEM8q9TgQ
# 2OC7gQEmhweVJ7yuKJlQBH7P7Pg5RiqgV3cSonJ+OM4kFHbP3gPLiyzssSQdRuPY
# 1mIWoGg9i7Y4ZC8ST7WhpSyc0pns2XsUe1XsIjaUcGu7zd7gg97eCUiLRdVklPmp
# XobH9CEAWakRUGNICYN2AgjhRTC4j3KJfqMkU04R6Toyh4/Toswm1uoDcGr5laYn
# TfcX3u5WnJqJLhuPe8Uj9kGAOcyo0O1mNwDa+LhFEzB6CB32+wfJMumfr6degvLT
# e8x55urQLeTjimBQgS49BSUkhFN7ois3cZyNpnrMca5AZaC7pLI72vuqSsSlLalG
# OcZmPHZGYJqZ0BacN274OZ80Q8B11iNokns9Od348bMb5Z4fihxaBWebl8kWEi2O
# PvQImOAeq3nt7UWJBzJYLAGEpfasaA3ZQgIcEXdD+uwo6ymMzDY6UamFOfYqYWXk
# ntxDGu7ngD2ugKUuccYKJJRiiz+LAUcj90BVcSHRLQop9N8zoALr/1sJuwPrVAtx
# HNEgSW+AKBqIxYWM4Ev32l6agSUAezLMbq5f3d8x9qzT031jMDT+sUAoCw0M5wVt
# CUQcqINPuYjbS1WgJyZIiEkBMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGZ4wghmaAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAOvMEAOTKNNBUEAAAAAA68wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBWjYL0+f7Zxz6QmUJQ5Ilgt
# OSYZYqaYAJcLHhSezxp7MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAUKANqQSIGuXkvu0Algvwmx0Xs/YN4e4jVKqfIZ5ztHxltUj04QUDXo1I
# WWBzT+IaVB9V6Mwkhq8QNnrGilJlNfwz2JTD6uKOHKh94cMfGgu6EawjUw/sUT0B
# vl66xrIMfrkR7Oc7rjjWsOb+MWz1uAYvSb4gXqXKCk60+oRJLc1jLKG7hoBVp2EE
# oM9dGx2jwMWojyp8lSD92l1qxr4KGc7esRC1NfeHDj42t/K4QhylVV7G07usGQyQ
# undyMT9t5W/nYXZQk+axR8vhG5NG7SgBfVu7BfS98LZG8OHdAJwXnAZyCRugfuhZ
# RsQd/ZOe1Vcej81w93Y/fwBn+Wz9Q6GCFygwghckBgorBgEEAYI3AwMBMYIXFDCC
# FxAGCSqGSIb3DQEHAqCCFwEwghb9AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFYBgsq
# hkiG9w0BCRABBKCCAUcEggFDMIIBPwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCEGZr7nNkebSbAeJBdTWn1XxopKqxVV502gQvEwdWI6gIGZdY1kcdn
# GBIyMDI0MDMxMjA4NDkxNS40M1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVs
# YW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046
# RkM0MS00QkQ0LUQyMjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAeKZmZXx3OMg6wABAAAB4jANBgkq
# hkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMzEw
# MTIxOTA3MjVaFw0yNTAxMTAxOTA3MjVaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVy
# YXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEtNEJE
# NC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtWO1mFX6QWZvxwpCmDabOKwO
# VEj3vwZvZqYa9sCYJ3TglUZ5N79AbMzwptCswOiXsMLuNLTcmRys+xaL1alXCwhy
# RFDwCRfWJ0Eb0eHIKykBq9+6/PnmSGXtus9DHsf31QluwTfAyamYlqw9amAXTnNm
# W+lZANQsNwhjKXmVcjgdVnk3oxLFY7zPBaviv3GQyZRezsgLEMmvlrf1JJ48AlEj
# LOdohzRbNnowVxNHMss3I8ETgqtW/UsV33oU3EDPCd61J4+DzwSZF7OvZPcdMUSW
# d4lfJBh3phDt4IhzvKWVahjTcISD2CGiun2pQpwFR8VxLhcSV/cZIRGeXMmwruz9
# kY9Th1odPaNYahiFrZAI6aSCM6YEUKpAUXAWaw+tmPh5CzNjGrhzgeo+dS7iFPhq
# qm9Rneog5dt3JTjak0v3dyfSs9NOV45Sw5BuC+VF22EUIF6nF9vqduynd9xlo8F9
# Nu1dVryctC4wIGrJ+x5u6qdvCP6UdB+oqmK+nJ3soJYAKiPvxdTBirLUfJidK1OZ
# 7hP28rq7Y78pOF9E54keJKDjjKYWP7fghwUSE+iBoq802xNWbhBuqmELKSevAHKq
# isEIsfpuWVG0kwnCa7sZF1NCwjHYcwqqmES2lKbXPe58BJ0+uA+GxAhEWQdka6KE
# vUmOPgu7cJsCaFrSU6sCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBREhA4R2r7tB2yW
# m0mIJE2leAnaBTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMI
# MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEA5FREMatVFNue6V+y
# DZxOzLKHthe+FVTs1kyQhMBBiwUQ9WC9K+ILKWvlqneRrvpjPS3/qXG5zMjrDu1e
# ryfhbFRSByPnACGc2iuGcPyWNiptyTft+CBgrf7ATAuE/U8YLm29crTFiiZTWdT6
# Vc7L1lGdKEj8dl0WvDayuC2xtajD04y4ANLmWDuiStdrZ1oI4afG5oPUg77rkTuq
# /Y7RbSwaPsBZ06M12l7E+uykvYoRw4x4lWaST87SBqeEXPMcCdaO01ad5TXVZDoH
# G/w6k3V9j3DNCiLJyC844kz3eh3nkQZ5fF8Xxuh8tWVQTfMiKShJ537yzrU0M/7H
# 1EzJrabAr9izXF28OVlMed0gqyx+a7e+79r4EV/a4ijJxVO8FCm/92tEkPrx6jjT
# WaQJEWSbL/4GZCVGvHatqmoC7mTQ16/6JR0FQqZf+I5opnvm+5CDuEKIEDnEiblk
# hcNKVfjvDAVqvf8GBPCe0yr2trpBEB5L+j+5haSa+q8TwCrfxCYqBOIGdZJL+5U9
# xocTICufIWHkb6p4IaYvjgx8ScUSHFzexo+ZeF7oyFKAIgYlRkMDvffqdAPx+fjL
# rnfgt6X4u5PkXlsW3SYvB34fkbEbM5tmab9zekRa0e/W6Dt1L8N+tx3WyfYTiCTh
# bUvWN1EFsr3HCQybBj4Idl4xK8EwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZ
# AAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVa
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1
# V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9
# alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmv
# Haus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928
# jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3t
# pK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEe
# HT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26o
# ElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4C
# vEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ug
# poMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXps
# xREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0C
# AwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYE
# FCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtT
# NRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBD
# AEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZW
# y4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5t
# aWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAt
# MDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0y
# My5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pc
# FLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpT
# Td2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0j
# VOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3
# +SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmR
# sqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSw
# ethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5b
# RAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmx
# aQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsX
# HRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0
# W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0
# HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFu
# ZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZD
# NDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloiMKAQEwBwYFKw4DAhoDFQAWm5lp+nRuekl0iF+IHV3ylOiGb6CBgzCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA
# 6Zpn9jAiGA8yMDI0MDMxMjEzMzQ0NloYDzIwMjQwMzEzMTMzNDQ2WjB0MDoGCisG
# AQQBhFkKBAExLDAqMAoCBQDpmmf2AgEAMAcCAQACAhQSMAcCAQACAhIuMAoCBQDp
# m7l2AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMH
# oSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAVtVMQyFd8vqV9M7ZFbhl
# GOAsZ74kkyIGDDXoLPGYuDp3unxXSzSYyX1PQuFdN/TbGtzUc7W/gdI9uuVeJ86Q
# /DDwB9cWrG3YEvxRnL2Rw8XpBzzCoKoYxZLKEyYOzGuDqREJ4vo6jFL42Qv650/7
# PJbNaYxuk/TJtVhPxgOIcFExggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAeKZmZXx3OMg6wABAAAB4jANBglghkgBZQMEAgEF
# AKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEi
# BCAOJp2qNP9YAUFPTZC2DQJzgZUJuL+27CnTBEDlAAFHwTCB+gYLKoZIhvcNAQkQ
# Ai8xgeowgecwgeQwgb0EICuJKkoQ/Sa4xsFQRM4Ogvh3ktToj9uO5whmQ4kIj3//
# MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHimZmV
# 8dzjIOsAAQAAAeIwIgQg3REqDfncLwFv6M1nZ2EhOk/B4Za4bGsNYmpNWwSvk+Aw
# DQYJKoZIhvcNAQELBQAEggIAnXI0ChJZtRUzMGKBW87gCp+5jSiMjPfFAomvS15O
# AQIvoaKyukg2Ab7CkFsE7gyqmbQoxxY2NvDiJdrVwDpHfVZshyXLMux3ESqB1VKb
# Whb2N0hlCEkXtdi991OzXF+FNmC1XjYf/FMiiNnkfy0wTpMzt0mBhFi/QsErz8ne
# 8ZPB3vHeiMphXm3ApoRaxQZFUINBcLqdxqIdn+91b9yK2t1zXPh1BwBZ0SRGP+Gw
# cq/+JCPdWfWyAL8/UzDwcRvpaG639yU3vvC7ZbGvXaaIBfhLi3hiG1QzNAVFgFKh
# efHWoQpqbJCi+w+qvensswWZsVvgqmMESbsl1/MFb8TC6/PSf77onTQ+nlIISfyq
# 7EnxUr45zqjKunRyIfCydefoQWaMW2IzwQQg1Cs43y8FdtNUIYEcBIChOrT4lSPD
# Ax5aajd2cDyUya92QWJKHZav5lEq+jFNXPDTavH5sWKMoTGwzu0G6t5/Ed9vmcYR
# VEzN7nQmL1pgtBRf4n8sgEs6Imb2u4hVS1DSZ6HaA2egZmC6jTb+gTul5P2sXzPX
# iLfGvrU4H5ycD7nCRDqnJyLKQcSHsgzH9H32BnjzNBju0v5l8OXh9Kn+ijhEXTF+
# g2f8vH7QYFInGt+xE3oV3Ky6cq9gqIG9R/DerQstUz3jI8mJMCME2ZYz2jW7+hTu
# fUs=
# SIG # End signature block
