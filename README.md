# Veracrypt-detector

A PowerShell-based detection tool for identifying VeraCrypt and TrueCrypt encryption software artifacts on Windows systems. Designed for cybersecurity analysts, digital forensics investigators, and incident response teams.

## Overview

This script performs comprehensive detection of encryption software artifacts including container files, running processes, registry keys, mounted volumes, and recent file access activity. It's particularly useful for incident response investigations where encrypted storage may be involved.

## Features

- **Container Detection**: Identifies .hc, .tc, .vol files and suspicious binary files
- **Process Monitoring**: Detects running VeraCrypt/TrueCrypt processes and services
- **Registry Analysis**: Examines registry keys and configuration data
- **Volume Detection**: Identifies mounted encrypted volumes and network drives
- **Activity Tracking**: Analyzes recent file access through registry forensics
- **Network Analysis**: Monitors network connections from encryption processes
- **Forensic Integration**: SHA256 hashing and JSON export capabilities

## Requirements

- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator rights recommended for complete system access
- **OS**: Windows (tested on Windows 10/11 and Server editions)

## Usage

### Basic Detection
```powershell
Detect-VeraCryptArtifacts
```
Performs standard detection scan with default output directory (`Output\VeraCryptArtifacts`).

### Custom Output Directory with Hashing
```powershell
Detect-VeraCryptArtifacts -OutputDir "C:\Forensics\Case001" -IncludeHashes
```
Runs detection with SHA256 hash calculation for forensic validation.

### Comprehensive Deep Scan
```powershell
Detect-VeraCryptArtifacts -DeepScan -ExportJSON
```
Performs thorough analysis with JSON export for SIEM integration.

### Advanced Investigation
```powershell
$Results = Detect-VeraCryptArtifacts -DeepScan -IncludeHashes -ExportJSON -OutputDir "C:\IR\Investigation"
Write-Host "Found $($Results.ContainersFound) containers totaling $($Results.TotalContainerSizeGB) GB"
```
Complete forensic scan with programmatic result analysis.

## Output Structure

The script returns a PSCustomObject with the following properties:

- **ContainersFound**: Number of detected container files
- **TotalContainerSizeGB**: Combined size of containers in GB
- **ProcessesRunning**: Count of active VeraCrypt/TrueCrypt processes
- **RegistryKeysFound**: Number of related registry artifacts
- **MountedVolumesFound**: Count of potential encrypted volumes
- **TotalAlerts**: Total detection alerts generated
- **ContainerPaths**: Array of container file locations
- **ProcessDetails**: Detailed process information
- **AlertsList**: Comprehensive alert details
- **LogFile**: Path to generated log file
- **JsonFile**: Path to JSON export (if enabled)
- **RecentFiles**: Recently accessed encryption files

## Deep Scan Features

When `-DeepScan` is enabled, the script performs:

- **Suspicious File Detection**: Analysis based on size patterns and file headers
- **Binary Header Analysis**: Cryptographic signature detection
- **Registry Parsing**: Recent document registry analysis and decoding
- **Shortcut Analysis**: LNK file examination for encryption software usage
- **Network Monitoring**: Connection tracking for encryption processes

## Operational Considerations

### Performance
- Large drives may require significant scan time
- Hash calculation increases processing duration for large files
- Deep scan mode substantially increases analysis time

### Security
- Run with elevated privileges for complete system access
- Binary analysis may trigger antivirus alerts
- Network drives are included in volume analysis

### Forensics
- Container files may use non-standard extensions as camouflage
- Hidden and system files are included in analysis
- Registry artifacts persist after software removal
- Recent activity detection works even with deleted containers
- Network connections only detected for currently running processes

## Integration

### SIEM Integration
Use `-ExportJSON` parameter to generate JSON output compatible with:
- Splunk
- Elastic Stack
- Microsoft Sentinel
- Custom log analysis platforms

### Automated Workflows
The script can be integrated into:
- Incident response playbooks
- Scheduled security scans
- Forensic investigation workflows
- Threat hunting activities

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for legitimate cybersecurity, digital forensics, and incident response activities. Users are responsible for ensuring compliance with applicable laws and organizational policies when deploying this script.

## Support

For issues, questions, or feature requests, please:
- Open an issue on GitHub
- Provide detailed information about your environment
- Include relevant log excerpts (sanitized of sensitive data)
