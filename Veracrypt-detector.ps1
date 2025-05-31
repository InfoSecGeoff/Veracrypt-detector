<#
.SYNOPSIS
    Detects VeraCrypt and TrueCrypt artifacts on Windows systems for digital forensics and incident response investigations.

.DESCRIPTION
    This PowerShell function performs comprehensive detection of VeraCrypt/TrueCrypt encryption software artifacts including:
    - Container files (.hc, .tc, .vol extensions and suspicious binary files)
    - Running processes and installed services
    - Registry keys and configuration data
    - Mounted encrypted volumes and network drives
    - Recent file access activity through registry analysis
    - Network connections from encryption processes
    
    The script is designed for cybersecurity analysts, digital forensics investigators, and incident response teams
    to identify potential use of disk encryption software on Windows endpoints.

.PARAMETER OutputDir
    Specifies the directory path where detection results will be saved.
    Default: "Output\VeraCryptArtifacts"
    The directory will be created automatically if it doesn't exist.

.PARAMETER IncludeHashes
    Switch parameter that enables SHA256 hash calculation for detected container files.
    Use this for forensic validation and malware analysis workflows.
    Warning: Hash calculation may significantly increase scan time for large files.

.PARAMETER DeepScan
    Switch parameter that enables comprehensive analysis:
    - Suspicious file detection based on size patterns and headers
    - Binary header analysis for crypto signatures
    - Recent document registry parsing and decoding
    - Shortcut file analysis
    - Network connection tracking for encryption processes
    
    Recommended for thorough investigations but increases scan duration.

.PARAMETER ExportJSON
    Switch parameter that exports results in JSON format alongside the standard log file.
    Useful for integration with SIEM systems, automated analysis tools, or custom reporting.

.OUTPUTS
    PSCustomObject containing detection summary with the following properties:
    - ContainersFound: Number of container files detected
    - TotalContainerSizeGB: Combined size of all containers in GB
    - ProcessesRunning: Number of VeraCrypt/TrueCrypt processes
    - RegistryKeysFound: Number of related registry artifacts
    - MountedVolumesFound: Number of potential encrypted volumes
    - TotalAlerts: Total number of detection alerts
    - ContainerPaths: Array of detected container file paths
    - ProcessDetails: Array of process information
    - AlertsList: Array of all generated alerts
    - LogFile: Path to generated log file
    - JsonFile: Path to JSON export (if enabled)
    - RecentFiles: Array of recently accessed encryption files

.EXAMPLE
    Veracrypt-Detector
    
    Performs basic detection scan with default settings. Results saved to "Output\VeraCryptArtifacts".

.EXAMPLE
    Veracrypt-Detector -OutputDir "C:\Forensics\Case001" -IncludeHashes
    
    Runs detection with SHA256 hash calculation enabled, saving results to custom directory.

.EXAMPLE
    Veracrypt-Detector -DeepScan -ExportJSON
    
    Performs comprehensive deep scan with JSON export for detailed forensic analysis.

.EXAMPLE
    $Results = Veracrypt-Detector -DeepScan -IncludeHashes -ExportJSON -OutputDir "C:\IR\Investigation"
    Write-Host "Found $($Results.ContainersFound) containers totaling $($Results.TotalContainerSizeGB) GB"
    
    Stores results in variable for programmatic analysis and displays summary statistics.

.NOTES
    File Name      : Veracrypt-Detector.ps1
    Author         : Geoff Tankersley
    Prerequisite   : PowerShell 5.1+, Administrator privileges recommended for access of processor and registry information
    
    OPERATIONAL SECURITY CONSIDERATIONS:
    - Run with elevated privileges for complete system access
    - Large drives may require significant scan time
    - Network drives are included in volume analysis
    - Registry analysis may detect historical usage even after software removal
    - Deep scan performs binary file analysis which may trigger AV alerts
    
    FORENSIC NOTES:
    - Container files may be disguised with non-standard extensions
    - Hidden and system files are included in scan
    - Recent activity detection works even if containers are deleted
    - Registry artifacts persist after software uninstallation
    - Network connections are only detected for currently running processes 
#>

function Veracrypt-Detector {
    param (
        [string]$OutputDir = "Output\VeraCryptArtifacts",
        [switch]$IncludeHashes,
        [switch]$DeepScan,
        [switch]$ExportJSON
    )

    $ContainerPatterns = @("*.hc", "*.tc", "*veracrypt*", "*.vol")
    $SuspiciousExtensions = @("*.dat", "*.bin", "*.img", "*.container")
    
    if (!(Test-Path -Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $Results = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        Containers = @()
        Processes = @()
        Services = @()
        Registry = @()
        MountedVolumes = @()
        RecentActivity = @()
        NetworkConnections = @()
        Alerts = @()
        Summary = @{}
    }

    Write-Host "Starting VeraCrypt detection on $($env:COMPUTERNAME)" -ForegroundColor Yellow
    
    # Container search
    Write-Host "Scanning drives..." -ForegroundColor Cyan
    $Drives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 -and $_.Size -gt 0 }
    
    foreach ($Drive in $Drives) {
        $DriveLetter = $Drive.DeviceID
        Write-Host "  Checking $DriveLetter" -ForegroundColor Gray
        
        try {
            foreach ($Pattern in $ContainerPatterns) {
                $Files = Get-ChildItem -Path $DriveLetter -Filter $Pattern -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -gt 1MB }
                
                foreach ($File in $Files) {
                    $Hash = "Not calculated"
                    if ($IncludeHashes) {
                        try {
                            $Hash = (Get-FileHash -Path $File.FullName -Algorithm SHA256).Hash
                        } catch {
                            $Hash = "Hash calculation failed"
                        }
                    }
                    
                    $ContainerInfo = @{
                        Path = $File.FullName
                        Size = $File.Length
                        SizeGB = [math]::Round($File.Length / 1GB, 2)
                        Created = $File.CreationTime
                        Modified = $File.LastWriteTime
                        Accessed = $File.LastAccessTime
                        Attributes = $File.Attributes.ToString()
                        Extension = $File.Extension
                        Hash = $Hash
                        IsHidden = ($File.Attributes -band [System.IO.FileAttributes]::Hidden) -eq [System.IO.FileAttributes]::Hidden
                    }
                    $Results.Containers += $ContainerInfo
                    $Results.Alerts += "Container found: $($File.FullName) ($($ContainerInfo.SizeGB) GB)"
                }
            }

            if ($DeepScan) {
                foreach ($Pattern in $SuspiciousExtensions) {
                    $SuspiciousFiles = Get-ChildItem -Path $DriveLetter -Filter $Pattern -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.Length -gt 100MB -and $_.Length % 512 -eq 0 }
                    
                    foreach ($File in $SuspiciousFiles) {
                        try {
                            $FileBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                            if ($FileBytes.Length -ge 64) {
                                $Header = $FileBytes[0..63]
                                $HeaderHex = ($Header | ForEach-Object { $_.ToString("X2") }) -join ""
                                
                                if ($HeaderHex -match "VERA|TRUE|CRYPT" -or $File.Length -gt 1GB) {
                                    $SuspiciousInfo = @{
                                        Path = $File.FullName
                                        Size = $File.Length
                                        SizeGB = [math]::Round($File.Length / 1GB, 2)
                                        Created = $File.CreationTime
                                        Modified = $File.LastWriteTime
                                        Reason = "Suspicious characteristics"
                                        HeaderSample = $HeaderHex.Substring(0, [math]::Min(32, $HeaderHex.Length))
                                    }
                                    $Results.Containers += $SuspiciousInfo
                                    $Results.Alerts += "Suspicious file: $($File.FullName)"
                                }
                            }
                        } catch {
                            # File access issues, skip
                        }
                    }
                }
            }
        } catch {
            $Results.Alerts += "Drive scan error $DriveLetter : $($_.Exception.Message)"
        }
    }

    # Process detection
    Write-Host "Checking processes..." -ForegroundColor Cyan
    $ProcessNames = @("VeraCrypt", "TrueCrypt", "veracrypt", "truecrypt")
    foreach ($ProcessName in $ProcessNames) {
        $Processes = Get-Process -Name "*$ProcessName*" -ErrorAction SilentlyContinue
        foreach ($Process in $Processes) {
            $ProcessPath = "Access Denied"
            try {
                if ($Process.MainModule) {
                    $ProcessPath = $Process.MainModule.FileName
                }
            } catch {}
            
            $CommandLine = "Not available"
            try {
                $WmiProcess = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -eq $Process.Id }
                if ($WmiProcess) {
                    $CommandLine = $WmiProcess.CommandLine
                }
            } catch {}
            
            $ProcessInfo = @{
                ProcessName = $Process.ProcessName
                PID = $Process.Id
                Path = $ProcessPath
                StartTime = $Process.StartTime
                WorkingSet = [math]::Round($Process.WorkingSet64 / 1MB, 2)
                CommandLine = $CommandLine
            }
            $Results.Processes += $ProcessInfo
            $Results.Alerts += "Process running: $($Process.ProcessName) (PID: $($Process.Id))"
        }
    }

    # Service check
    $Services = Get-Service | Where-Object { $_.Name -match "veracrypt|truecrypt" }
    foreach ($Service in $Services) {
        $ServiceInfo = @{
            Name = $Service.Name
            DisplayName = $Service.DisplayName
            Status = $Service.Status.ToString()
            StartType = $Service.StartType.ToString()
        }
        $Results.Services += $ServiceInfo
    }

    # Registry analysis
    Write-Host "Checking registry..." -ForegroundColor Cyan
    $RegistryPaths = @(
        @{ Path = "HKCU:\Software\VeraCrypt"; Type = "User Settings" },
        @{ Path = "HKLM:\Software\VeraCrypt"; Type = "System Settings" },
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt"; Type = "Installation" },
        @{ Path = "HKCU:\Software\Classes\.hc"; Type = "File Association" },
        @{ Path = "HKLM:\System\CurrentControlSet\Services\veracrypt"; Type = "Service" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"; Type = "Recent Documents" }
    )

    foreach ($RegPath in $RegistryPaths) {
        try {
            if (Test-Path $RegPath.Path) {
                $RegInfo = @{
                    Path = $RegPath.Path
                    Type = $RegPath.Type
                    Values = @{}
                    LastWriteTime = (Get-Item $RegPath.Path).LastWriteTime
                }
                
                $Properties = Get-ItemProperty -Path $RegPath.Path -ErrorAction SilentlyContinue
                if ($Properties) {
                    foreach ($Property in $Properties.PSObject.Properties) {
                        if ($Property.Name -notmatch "^PS") {
                            $RegInfo.Values[$Property.Name] = $Property.Value
                        }
                    }
                }
                
                $Results.Registry += $RegInfo
                $Results.Alerts += "Registry artifact: $($RegPath.Path)"
            }
        } catch {}
    }

    # Locate all volumes
    Write-Host "Checking mounted volumes..." -ForegroundColor Cyan
    
    # Locate standard VeraCrypt volumes
    $MountedVolumes = Get-CimInstance Win32_Volume | Where-Object { 
        $_.FileSystem -and ($_.Label -match "veracrypt|truecrypt" -or ($_.DriveLetter -and (Test-Path "$($_.DriveLetter)\VERACRYPT")))
    }
    
    foreach ($Volume in $MountedVolumes) {
        $VolumeInfo = @{
            DriveLetter = $Volume.DriveLetter
            Label = $Volume.Label
            FileSystem = $Volume.FileSystem
            Size = [math]::Round($Volume.Capacity / 1GB, 2)
            FreeSpace = [math]::Round($Volume.FreeSpace / 1GB, 2)
            DeviceID = $Volume.DeviceID
            Type = "Mounted Volume"
        }
        $Results.MountedVolumes += $VolumeInfo
        $Results.Alerts += "Mounted volume: $($Volume.DriveLetter)"
    }

    # Locate all network drives
    $MappedDrives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 4 }
    foreach ($Drive in $MappedDrives) {
        try {
            $NetworkPath = (Get-PSDrive $Drive.DeviceID.Replace(":", "") -ErrorAction SilentlyContinue).DisplayRoot
            if ($NetworkPath) {
                $DriveInfo = @{
                    DriveLetter = $Drive.DeviceID
                    Label = $Drive.VolumeName
                    FileSystem = $Drive.FileSystem
                    Size = if ($Drive.Size) { [math]::Round($Drive.Size / 1GB, 2) } else { 0 }
                    FreeSpace = if ($Drive.FreeSpace) { [math]::Round($Drive.FreeSpace / 1GB, 2) } else { 0 }
                    DeviceID = $Drive.DeviceID
                    NetworkPath = $NetworkPath
                    Type = "Network Drive"
                }
                $Results.MountedVolumes += $DriveInfo
                $Results.Alerts += "Network drive: $($Drive.DeviceID) -> $NetworkPath"
            }
        } catch {}
    }

    # Check drives for VeraCrypt markers
    $AllDrives = Get-CimInstance Win32_LogicalDisk
    foreach ($Drive in $AllDrives) {
        if ($Drive.DriveType -eq 3 -and $Drive.DeviceID) {
            try {
                $TestPaths = @(
                    "$($Drive.DeviceID)\VERACRYPT",
                    "$($Drive.DeviceID)\System Volume Information"
                )
                
                $HasMarkers = $false
                foreach ($TestPath in $TestPaths) {
                    if (Test-Path $TestPath) {
                        $HasMarkers = $true
                        break
                    }
                }
                
                if ($HasMarkers -or ($Drive.Size -and $Drive.Size -lt 100GB)) {
                    $DriveInfo = @{
                        DriveLetter = $Drive.DeviceID
                        Label = $Drive.VolumeName
                        FileSystem = $Drive.FileSystem
                        Size = if ($Drive.Size) { [math]::Round($Drive.Size / 1GB, 2) } else { 0 }
                        FreeSpace = if ($Drive.FreeSpace) { [math]::Round($Drive.FreeSpace / 1GB, 2) } else { 0 }
                        DeviceID = $Drive.DeviceID
                        Type = "Potential Volume"
                        HasVeraCryptMarkers = $HasMarkers
                    }
                    
                    $Exists = $Results.MountedVolumes | Where-Object { $_.DriveLetter -eq $Drive.DeviceID }
                    if (-not $Exists) {
                        $Results.MountedVolumes += $DriveInfo
                        if ($HasMarkers) {
                            $Results.Alerts += "Drive markers found: $($Drive.DeviceID)"
                        }
                    }
                }
            } catch {}
        }
    }

    # Recent activity analysis
    if ($DeepScan) {
        Write-Host "Analyzing recent activity..." -ForegroundColor Cyan
        
        $RecentDocsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        if (Test-Path $RecentDocsPath) {
            try {
                $RecentExtensions = Get-ChildItem $RecentDocsPath -ErrorAction SilentlyContinue
                
                foreach ($ExtKey in $RecentExtensions) {
                    $Extension = $ExtKey.PSChildName
                    if ($Extension -match "^(hc|tc|dat|bin|vol)$" -and $Extension.Length -le 10) {
                        Write-Host "  Found extension: .$Extension" -ForegroundColor Yellow
                        
                        try {
                            $ExtProperties = Get-ItemProperty -Path $ExtKey.PSPath -ErrorAction SilentlyContinue
                            foreach ($Property in $ExtProperties.PSObject.Properties) {
                                if ($Property.Name -match "^\d+$" -and $Property.Value) {
                                    try {
                                        $BinaryData = $Property.Value
                                        if ($BinaryData -is [array] -and $BinaryData.Length -gt 4) {
                                            $DecodedString = ""
                                            $CleanString = ""
                                            
                                            try {
                                                $DecodedString = [System.Text.Encoding]::Unicode.GetString($BinaryData)
                                                $CleanString = ($DecodedString -replace '\x00', '').Trim()
                                            } catch {
                                                for ($i = 0; $i -lt $BinaryData.Length - 1; $i += 2) {
                                                    $Char = [char]([int]$BinaryData[$i] + [int]$BinaryData[$i + 1] * 256)
                                                    if ($Char -match '[a-zA-Z0-9\\.:_\-/]') {
                                                        $CleanString += $Char
                                                    }
                                                }
                                            }
                                            
                                            if ($CleanString -match "\.hc|\.tc|veracrypt|truecrypt|[A-Z]:\\|\\\\.*\\.*" -and $CleanString.Length -gt 3) {
                                                $FilePath = $CleanString
                                                if ($CleanString -match '([A-Z]:\\[^\\]+(?:\\[^\\]+)*\.[a-zA-Z0-9]+)') {
                                                    $FilePath = $matches[1]
                                                } elseif ($CleanString -match '(\\\\[^\\]+\\[^\\]+(?:\\[^\\]+)*\.[a-zA-Z0-9]+)') {
                                                    $FilePath = $matches[1]
                                                }
                                                
                                                Write-Host "    Found path: $FilePath" -ForegroundColor Yellow
                                                
                                                $RecentInfo = @{
                                                    Extension = $Extension
                                                    RegistryKey = $ExtKey.PSPath
                                                    DecodedPath = $FilePath
                                                    RawDecoded = $CleanString
                                                    BinaryLength = $BinaryData.Length
                                                    PropertyIndex = $Property.Name
                                                    DetectionReason = "Recent file access"
                                                }
                                                $Results.RecentActivity += $RecentInfo
                                                $Results.Alerts += "Recent file: $FilePath"
                                            } elseif ($Extension -match "hc|tc" -and $CleanString.Length -gt 3) {
                                                $RecentInfo = @{
                                                    Extension = $Extension
                                                    RegistryKey = $ExtKey.PSPath
                                                    DecodedPath = $CleanString
                                                    RawDecoded = $CleanString
                                                    BinaryLength = $BinaryData.Length
                                                    PropertyIndex = $Property.Name
                                                    DetectionReason = "Suspicious extension activity"
                                                }
                                                $Results.RecentActivity += $RecentInfo
                                                $Results.Alerts += "Suspicious activity: $Extension extension"
                                            }
                                        }
                                    } catch {}
                                }
                            }
                        } catch {}
                    }
                }

                # Check main recent docs for signatures
                $MainRecentProps = Get-ItemProperty -Path $RecentDocsPath -ErrorAction SilentlyContinue
                if ($MainRecentProps) {
                    foreach ($Property in $MainRecentProps.PSObject.Properties) {
                        if ($Property.Name -match "^\d+$" -and $Property.Value -is [array]) {
                            try {
                                $BinaryData = $Property.Value
                                $HexString = ($BinaryData | ForEach-Object { $_.ToString("X2") }) -join ""
                                
                                if ($HexString -match "007600650072006100630072007900700074|0074007200750065006300720079007000740") {
                                    $Results.Alerts += "Crypto signature in recent docs"
                                }
                            } catch {}
                        }
                    }
                }
            } catch {}
        }
        
        # Check shortcuts
        $RecentPath = "$env:APPDATA\Microsoft\Windows\Recent"
        if (Test-Path $RecentPath) {
            $RecentDocs = Get-ChildItem $RecentPath -Filter "*.lnk" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "veracrypt|truecrypt|\.hc|\.tc" }
            
            foreach ($Doc in $RecentDocs) {
                $TargetPath = "Unknown"
                try {
                    $Shell = New-Object -ComObject WScript.Shell
                    $Shortcut = $Shell.CreateShortcut($Doc.FullName)
                    $TargetPath = $Shortcut.TargetPath
                } catch {}
                
                $RecentInfo = @{
                    LinkFile = $Doc.FullName
                    TargetFile = $TargetPath
                    AccessTime = $Doc.LastAccessTime
                    CreationTime = $Doc.CreationTime
                    DetectionReason = "Shortcut file"
                }
                $Results.RecentActivity += $RecentInfo
            }
        }

        # Network connections
        if ($Results.Processes.Count -gt 0) {
            $ProcessIDs = $Results.Processes | ForEach-Object { $_.PID }
            $Connections = Get-NetTCPConnection | Where-Object { 
                $_.OwningProcess -in $ProcessIDs
            }
            
            foreach ($Connection in $Connections) {
                $ConnInfo = @{
                    LocalAddress = $Connection.LocalAddress
                    LocalPort = $Connection.LocalPort
                    RemoteAddress = $Connection.RemoteAddress
                    RemotePort = $Connection.RemotePort
                    State = $Connection.State.ToString()
                    OwningProcess = $Connection.OwningProcess
                }
                $Results.NetworkConnections += $ConnInfo
            }
        }
    }


    $TotalSize = 0
    foreach ($Container in $Results.Containers) {
        if ($Container.Size -and $Container.Size -is [long]) {
            $TotalSize += $Container.Size
        }
    }
    
    $Results.Summary = @{
        ContainersFound = $Results.Containers.Count
        ProcessesRunning = $Results.Processes.Count
        ServicesFound = $Results.Services.Count
        RegistryKeysFound = $Results.Registry.Count
        MountedVolumesFound = $Results.MountedVolumes.Count
        TotalAlerts = $Results.Alerts.Count
        TotalContainerSize = $TotalSize
        TotalContainerSizeGB = [math]::Round($TotalSize / 1GB, 2)
    }

    # Output results
    $Timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $LogFile = Join-Path -Path $OutputDir -ChildPath "VeraCryptDetection-$Timestamp.log"
    
    # Log content
    $LogHeader = @"
VeraCrypt Detection Report
Generated: $($Results.Timestamp)
Host: $($Results.Hostname)
User: $($Results.Username)

Summary:
Containers: $($Results.Summary.ContainersFound)
Total Size: $($Results.Summary.TotalContainerSizeGB) GB
Processes: $($Results.Summary.ProcessesRunning)
Registry Keys: $($Results.Summary.RegistryKeysFound)
Volumes: $($Results.Summary.MountedVolumesFound)
Alerts: $($Results.Summary.TotalAlerts)

Alerts:
"@

    $AlertsSection = if ($Results.Alerts.Count -gt 0) {
        ($Results.Alerts | ForEach-Object { "- $_" }) -join "`n"
    } else {
        "None"
    }

    $ContainersSection = "`n`nContainers:`n"
    if ($Results.Containers.Count -gt 0) {
        foreach ($Container in $Results.Containers) {
            $ContainersSection += "Path: $($Container.Path)`n"
            $ContainersSection += "Size: $($Container.SizeGB) GB ($($Container.Size) bytes)`n"
            $ContainersSection += "Created: $($Container.Created)`n"
            $ContainersSection += "Modified: $($Container.Modified)`n"
            $ContainersSection += "Accessed: $($Container.Accessed)`n"
            $ContainersSection += "Extension: $($Container.Extension)`n"
            $ContainersSection += "Hidden: $($Container.IsHidden)`n"
            if ($Container.Hash -ne "Not calculated") {
                $ContainersSection += "SHA256: $($Container.Hash)`n"
            }
            if ($Container.Reason) {
                $ContainersSection += "Detection Reason: $($Container.Reason)`n"
            }
            if ($Container.HeaderSample) {
                $ContainersSection += "Header Sample: $($Container.HeaderSample)`n"
            }
            $ContainersSection += "----------------------------------------`n"
        }
    } else {
        $ContainersSection += "None found`n"
    }

    $ProcessesSection = "`nProcesses:`n"
    if ($Results.Processes.Count -gt 0) {
        foreach ($Process in $Results.Processes) {
            $ProcessesSection += "Process: $($Process.ProcessName) (PID: $($Process.PID))`n"
            $ProcessesSection += "Path: $($Process.Path)`n"
            $ProcessesSection += "Start Time: $($Process.StartTime)`n"
            $ProcessesSection += "Memory: $($Process.WorkingSet) MB`n"
            if ($Process.CommandLine -ne "Not available") {
                $ProcessesSection += "Command Line: $($Process.CommandLine)`n"
            }
            $ProcessesSection += "----------------------------------------`n"
        }
    } else {
        $ProcessesSection += "None running`n"
    }

    $ServicesSection = "`nServices:`n"
    if ($Results.Services.Count -gt 0) {
        foreach ($Service in $Results.Services) {
            $ServicesSection += "Service: $($Service.Name)`n"
            $ServicesSection += "Display Name: $($Service.DisplayName)`n"
            $ServicesSection += "Status: $($Service.Status)`n"
            $ServicesSection += "Start Type: $($Service.StartType)`n"
            $ServicesSection += "----------------------------------------`n"
        }
    } else {
        $ServicesSection += "None found`n"
    }

    $RegistrySection = "`nRegistry:`n"
    if ($Results.Registry.Count -gt 0) {
        foreach ($RegKey in $Results.Registry) {
            $RegistrySection += "Path: $($RegKey.Path)`n"
            $RegistrySection += "Type: $($RegKey.Type)`n"
            $RegistrySection += "Last Modified: $($RegKey.LastWriteTime)`n"
            $RegistrySection += "Values:`n"
            if ($RegKey.Values.Count -gt 0) {
                foreach ($Key in $RegKey.Values.Keys) {
                    $Value = $RegKey.Values[$Key]
                    $RegistrySection += "  $Key = $Value`n"
                }
            } else {
                $RegistrySection += "  None`n"
            }
            $RegistrySection += "----------------------------------------`n"
        }
    } else {
        $RegistrySection += "None found`n"
    }

    $VolumesSection = "`nVolumes:`n"
    if ($Results.MountedVolumes.Count -gt 0) {
        foreach ($Volume in $Results.MountedVolumes) {
            $VolumesSection += "Drive: $($Volume.DriveLetter)`n"
            $VolumesSection += "Label: $($Volume.Label)`n"
            $VolumesSection += "Type: $($Volume.Type)`n"
            $VolumesSection += "File System: $($Volume.FileSystem)`n"
            $VolumesSection += "Size: $($Volume.Size) GB`n"
            $VolumesSection += "Free: $($Volume.FreeSpace) GB`n"
            if ($Volume.NetworkPath) {
                $VolumesSection += "Network Path: $($Volume.NetworkPath)`n"
            }
            if ($Volume.HasVeraCryptMarkers) {
                $VolumesSection += "Markers: Yes`n"
            }
            $VolumesSection += "Device: $($Volume.DeviceID)`n"
            $VolumesSection += "----------------------------------------`n"
        }
    } else {
        $VolumesSection += "None found`n"
    }

    $LogContent = $LogHeader + $AlertsSection + $ContainersSection + $ProcessesSection + $ServicesSection + $RegistrySection + $VolumesSection
    $LogContent | Out-File -FilePath $LogFile -Encoding UTF8

    # JSON export
    if ($ExportJSON) {
        $JsonFile = Join-Path -Path $OutputDir -ChildPath "VeraCryptDetection-$Timestamp.json"
        $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonFile -Encoding UTF8
        Write-Host "JSON saved: $JsonFile" -ForegroundColor Green
    }

    # Console output
    Write-Host "`nVeraCrypt Detection Results" -ForegroundColor Yellow
    Write-Host "Host: $($Results.Hostname) | User: $($Results.Username)" -ForegroundColor Gray
    Write-Host "Completed: $($Results.Timestamp)" -ForegroundColor Gray
    
    if ($Results.Summary.TotalAlerts -gt 0) {
        Write-Host "`nAlerts: $($Results.Summary.TotalAlerts)" -ForegroundColor Red
        foreach ($Alert in $Results.Alerts) {
            Write-Host "  - $Alert" -ForegroundColor Yellow
        }
    } else {
        Write-Host "`nNo artifacts detected" -ForegroundColor Green
    }

    Write-Host "`nSummary:" -ForegroundColor Cyan
    Write-Host "  Containers: $($Results.Summary.ContainersFound) ($($Results.Summary.TotalContainerSizeGB) GB)" -ForegroundColor White
    Write-Host "  Processes: $($Results.Summary.ProcessesRunning)" -ForegroundColor White
    Write-Host "  Registry: $($Results.Summary.RegistryKeysFound)" -ForegroundColor White
    Write-Host "  Volumes: $($Results.Summary.MountedVolumesFound)" -ForegroundColor White

    # Container details
    if ($Results.Containers.Count -gt 0) {
        Write-Host "`nContainer Details:" -ForegroundColor Cyan
        foreach ($Container in $Results.Containers) {
            Write-Host "  Path: $($Container.Path)" -ForegroundColor White
            Write-Host "    Size: $($Container.SizeGB) GB ($($Container.Size) bytes)" -ForegroundColor Gray
            Write-Host "    Created: $($Container.Created)" -ForegroundColor Gray
            Write-Host "    Modified: $($Container.Modified)" -ForegroundColor Gray
            if ($Container.Hash -ne "Not calculated") {
                Write-Host "    SHA256: $($Container.Hash)" -ForegroundColor Gray
            }
            Write-Host ""
        }
    }

    # Process Summary
    if ($Results.Processes.Count -gt 0) {
        Write-Host "Process Details:" -ForegroundColor Cyan
        foreach ($Process in $Results.Processes) {
            Write-Host "  Process: $($Process.ProcessName) (PID: $($Process.PID))" -ForegroundColor White
            Write-Host "    Path: $($Process.Path)" -ForegroundColor Gray
            Write-Host "    Started: $($Process.StartTime)" -ForegroundColor Gray
            Write-Host "    Memory: $($Process.WorkingSet) MB" -ForegroundColor Gray
            if ($Process.CommandLine -and $Process.CommandLine -ne "Not available") {
                Write-Host "    Command: $($Process.CommandLine)" -ForegroundColor Gray
            }
            Write-Host ""
        }
    }

    # Registry Summary
    if ($Results.Registry.Count -gt 0) {
        Write-Host "Registry Artifacts:" -ForegroundColor Cyan
        foreach ($RegKey in $Results.Registry) {
            Write-Host "  Path: $($RegKey.Path)" -ForegroundColor White
            Write-Host "    Type: $($RegKey.Type)" -ForegroundColor Gray
            Write-Host "    Modified: $($RegKey.LastWriteTime)" -ForegroundColor Gray
            if ($RegKey.Values.Count -gt 0) {
                Write-Host "    Values:" -ForegroundColor Gray
                foreach ($Key in $RegKey.Values.Keys) {
                    $Value = $RegKey.Values[$Key]
                    if ($Value -is [array]) {
                        Write-Host "      $Key = [Array with $($Value.Count) items]" -ForegroundColor DarkGray
                    } else {
                        $DisplayValue = if ($Value.ToString().Length -gt 100) { 
                            $Value.ToString().Substring(0, 100) + "..." 
                        } else { 
                            $Value.ToString() 
                        }
                        Write-Host "      $Key = $DisplayValue" -ForegroundColor DarkGray
                    }
                }
            }
            Write-Host ""
        }
    }

    # Volume Summary
    if ($Results.MountedVolumes.Count -gt 0) {
        Write-Host "Volume Details:" -ForegroundColor Cyan
        foreach ($Volume in $Results.MountedVolumes) {
            Write-Host "  Drive: $($Volume.DriveLetter)" -ForegroundColor White
            Write-Host "    Type: $($Volume.Type)" -ForegroundColor Gray
            Write-Host "    Label: $($Volume.Label)" -ForegroundColor Gray
            Write-Host "    FileSystem: $($Volume.FileSystem)" -ForegroundColor Gray
            Write-Host "    Size: $($Volume.Size) GB (Free: $($Volume.FreeSpace) GB)" -ForegroundColor Gray
            if ($Volume.NetworkPath) {
                Write-Host "    Network Path: $($Volume.NetworkPath)" -ForegroundColor Gray
            }
            if ($Volume.HasVeraCryptMarkers) {
                Write-Host "    VeraCrypt Markers: Yes" -ForegroundColor Yellow
            }
            Write-Host "    Device: $($Volume.DeviceID)" -ForegroundColor Gray
            Write-Host ""
        }
    }

    # Activity Summary
    if ($DeepScan -and $Results.RecentActivity.Count -gt 0) {
        Write-Host "Recent Activity:" -ForegroundColor Cyan
        foreach ($Activity in $Results.RecentActivity) {
            if ($Activity.LinkFile) {
                Write-Host "  Shortcut: $($Activity.LinkFile)" -ForegroundColor White
                Write-Host "    Target: $($Activity.TargetFile)" -ForegroundColor Gray
                Write-Host "    Accessed: $($Activity.AccessTime)" -ForegroundColor Gray
            } elseif ($Activity.DecodedPath) {
                Write-Host "  Registry Entry: .$($Activity.Extension)" -ForegroundColor White
                Write-Host "    File Path: $($Activity.DecodedPath)" -ForegroundColor Gray
                if ($Activity.RawDecoded -ne $Activity.DecodedPath) {
                    Write-Host "    Raw Content: $($Activity.RawDecoded)" -ForegroundColor DarkGray
                }
                Write-Host "    Binary Length: $($Activity.BinaryLength) bytes" -ForegroundColor Gray
                Write-Host "    Registry Index: $($Activity.PropertyIndex)" -ForegroundColor Gray
                Write-Host "    Reason: $($Activity.DetectionReason)" -ForegroundColor Gray
            }
            Write-Host ""
        }
    }

    Write-Host "Log saved: $LogFile" -ForegroundColor Green
    
    # Final summary
    $DetailedSummary = @{
        ContainersFound = $Results.Summary.ContainersFound
        TotalContainerSizeGB = $Results.Summary.TotalContainerSizeGB
        ProcessesRunning = $Results.Summary.ProcessesRunning
        RegistryKeysFound = $Results.Summary.RegistryKeysFound
        MountedVolumesFound = $Results.Summary.MountedVolumesFound
        TotalAlerts = $Results.Summary.TotalAlerts
        ContainerPaths = $Results.Containers | ForEach-Object { $_.Path }
        ProcessDetails = $Results.Processes | ForEach-Object { "$($_.ProcessName) (PID: $($_.PID)) - $($_.Path)" }
        AlertsList = $Results.Alerts
        LogFile = $LogFile
        JsonFile = if ($ExportJSON) { $JsonFile } else { "Not generated" }
        RecentFiles = $Results.RecentActivity | ForEach-Object { 
            if ($_.DecodedPath) { 
                "$($_.Extension): $($_.DecodedPath)" 
            } else { 
                $_.LinkFile 
            } 
        }
    }
    
    Write-Host "`nFinal Summary:" -ForegroundColor Green
    Write-Host "  Containers: $($DetailedSummary.ContainersFound)" -ForegroundColor White
    Write-Host "  Size: $($DetailedSummary.TotalContainerSizeGB) GB" -ForegroundColor White
    Write-Host "  Processes: $($DetailedSummary.ProcessesRunning)" -ForegroundColor White
    Write-Host "  Registry: $($DetailedSummary.RegistryKeysFound)" -ForegroundColor White
    Write-Host "  Volumes: $($DetailedSummary.MountedVolumesFound)" -ForegroundColor White
    Write-Host "  Alerts: $($DetailedSummary.TotalAlerts)" -ForegroundColor White
    
    if ($DetailedSummary.ContainerPaths.Count -gt 0) {
        Write-Host "  Container Paths:" -ForegroundColor White
        foreach ($Path in $DetailedSummary.ContainerPaths) {
            Write-Host "    - $Path" -ForegroundColor Gray
        }
    }
    
    if ($DetailedSummary.RecentFiles.Count -gt 0) {
        Write-Host "  Recent Files:" -ForegroundColor White
        foreach ($File in $DetailedSummary.RecentFiles) {
            Write-Host "    - $File" -ForegroundColor Gray
        }
    }
    
    return $DetailedSummary
}

# Run detection
Veracrypt-Detector -DeepScan -IncludeHashes -ExportJSON
