<h1 align="center">ArteMon</h1>

<p align="center">

<img src="https://github.com/user-attachments/assets/2b005ce8-ba53-4009-a451-fa6940d8a8b5" width="600">

</p>


---

<p align="center">
 <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPLv3-purple.svg?&logo=none"></a>
 <a href="#"><img src="https://img.shields.io/badge/Windows-Live_Artifacts_Monitor-blue"></a>
 <a href="#"><img src="https://img.shields.io/badge/IP_Geolocation_Checker-129990"></a>
 <a href="#"><img src="https://img.shields.io/badge/Tabular_File_Formats-Output-2e5339"></a>
 <a href="#"><img src="https://img.shields.io/badge/IP_Based-Threat_Intelligence_Tool-644A07"></a>
 <a href="#"><img src="https://img.shields.io/badge/DFIR-Simulation_Exercise-3B0270"></a>
  <!-- <a href="https://baycysec.org/"><img src="https://img.shields.io/badge/BAY_Cyber_Security-Community_Contributions-59AC77"></a> -->
</p>


## [❓] About ArteMon

<p align="justify">ArteMon was developed to address a critical gap in modern Digital Forensics and Incident Response (DFIR). It is a real-time Windows artifact intelligence platform designed for investigators, responders, and educators who cannot afford to miss evidence that disappears in seconds.Unlike traditional snapshot-based forensic tools, ArteMon continuously monitors, detects, and correlates Windows artifacts as they change—capturing transient traces that are often lost before collection. By providing structured, event-driven visibility across registry keys, processes, scheduled tasks, event logs, and other core system components, it ensures that no critical activity goes unnoticed. </p>

<p align="justify">Beyond live artifact monitoring, ArteMon extends its capability into network intelligence and geographic correlation. Through a companion analysis component that operates on Linux environments, investigators can enrich forensic findings with IP-based contextual and geographic insights derived from captured network logs. For investigators, this architecture enables faster triage, stronger timelines, and complete visibility into system behavior as it unfolds. For educators, ArteMon provides a reproducible and interactive environment to demonstrate how attacker actions directly alter Windows artifacts—transforming theoretical lessons into tangible, observable evidence.</p>

By bridging operational DFIR, network intelligence, and education within a unified framework, ArteMon makes forensic analysis as fast and dynamic as the threats it pursues.

## [🔥] Motivations Behind ArteMon

<p align="justify">In Windows incident response, a single missed artifact can derail the entire investigation. A fleeting registry change, a dropped DLL, or a short-lived scheduled task can vanish before analysts even begin triage. It is breaking pivot chains and obscuring the real cause of compromise. Traditional forensic workflows rely on manual checks or delayed snapshots, leaving dangerous blind spots. Modern attackers exploit this observation gap, creating and erasing evidence faster than periodic tools can detect. The result is incomplete timelines, missed persistence mechanisms, and inconclusive analysis under intense time pressure. </p>

<p align="justify">For educators, the challenge is similar. Teaching Windows forensics rarely shows real-time cause-and-effect what actually changes when an attack runs. Without reproducible, observable demonstrations, students learn theory but miss the dynamic reality of Windows artifact behavior. Windows continuously emits a torrent of forensic signals from registry writes and process creations to event logs, prefetch, and LNK updates. Without real-time, event-driven monitoring, these signals fade into noise, and investigators lose sight of critical moments that define an attack. </p>

<p align="justify">There is a clear need for a solution that can capture, analyze, and visualize artifact changes as they happen <b>bridging the gap between investigation, automation, and education before the evidence disappears.</b></p>

## [📈] What's Next?
> [!TIP]
> Future research will extend ArteMon to Linux systems and further deepen its capability to monitor and interpret complex Windows artifacts.

## [🧠] Main Features

|No.|Main Features|Summary|
|:-:|:------------|:----|
|1. |Holmes Vision |A real-time Windows artifact monitoring and correlation engine that continuously detects and tracks changes across windows forensic artifacts. Below are Holmes Vision core detectors: <br>1.Process Detector.<br>2. Netstat Detector.<br>3. Filesystem Detector.<br>4. Registry Detector.<br>5. EventLog Detector.<br>6. LNK Detector.<br>7. Prefetch Detector.<br>8. Scheduled Task Detector.<br>9. Recycle Bin Detector.<br>10. Services Detector.<br>11. Startup Items Detector.<br>12. WMI Subscription Detector.|
|2. |Holmes Geo |<p align="justify">A companion module that can be deployed on Linux (including WSL) to perform IP geolocation analysis using network logs retrieved from ArteMon, providing contextual and geographic intelligence.</p>|

## [⚙️] Deployments & Usage

> ## Holmes Vision

> [!IMPORTANT]
> - Windows Powershell Terminal (Administrator privileges required)
> - Python 3.10+ installed and on your PATH

```ps1
# Run the installer (one-time)
.\arte.ps1

# Start ArteMon
python main.py
```

When the menu appears, choose one or more artifact IDs to monitor. To select a single artifact, type its number and press Enter (e.g. 3). To select multiple artifacts, separate IDs with commas (no spaces required), e.g.:
   
```ps1
3,4
```
After selection, press Enter. ArteMon will spin up detector threads. Wait until you see each detector listed with alive=True, for example:

```ps1
[*] Detector threads status:
  - registry: alive=True interval=2.0s
  - fs: alive=True interval=2.0s
```

4. This output confirms the corresponding monitoring threads are running.
5. Once detectors are running, you may launch adversary simulations or tests. See the sample simulations in ArteMon's WIKI:
- Our customized C-based ransomware sample [Abyssos](https://drive.google.com/drive/folders/1yrhIcZ5IpH5BR_mX-4rKrYpURPIbkejM?usp=drive_link)
- Our customized Golang-based ransomware sample [Kegembok](https://drive.google.com/drive/folders/1xlvRohfjZp1ReGFvFXuHh3cvWNIFn1aj?usp=drive_link)
- Our customized adversary simulation script attacks [Rizarru](https://drive.google.com/drive/folders/1YDI29V9U3G_0IwkJTzu0R1RFMLm-XjuS?usp=drive_link)

## [📃] Holmes Vision Operation Modes

|Mode|Detectors|Description|
|:--:|:-------|:---------|
|Realtime|`Process`, `LNK`, `Filesystem`, `EventLog`|Immediately reacts to changes as they occur.|
|Polling|`Netstat`, `Prefetch`, `SchTask`, `RecycleBin`, `Services`, `Startup Items`, `Registry`, `WMI Subscription`|Periodically collects and compares snapshots at defined intervals.|
|Hybrid|Filesystem|Combines real-time monitoring with periodic vaidation for higher reliability.|
---

> ## Holmes Geo

> [!WARNING]
> For security reasons, we recommend using your own Account ID and License Key for MaxMind DB and your own API Key for Virus Total. For guidance on how to obtain these, please refer to our [WIKI](https://github.com/baycysec/artemon/wiki/ArteMon-WIKI-Page).

```html
# Paste your MaxMind UserID and LicenseKey at install.sh script
21 ...
22 ...
23 UserId <<PASTE_ACCOUNT_ID_HERE>>
24 LicenseKey <<PASTE_LICENSE_KEY_HERE>>
25 EditionIDs GeoLite2-Country GeoLite2-City GeoLite2-ASN
26 DatabaseDirectory /usr/local/share/GeoIP
27 EOF'
28 ...
29 ...
```

> [!IMPORTANT]
> - Windows Powershell Terminal (Administrator privileges required)
> - Windows Subsystem for Linux (WSL) Installed.
> - Internet Access to Download Repositories and Dependencies.
> - A valid MaxMind Account (for API Credentials)

```bash
# At windows powershell terminal (with Administrator privileges).
wsl --install
wsl # launch newly installed Ubuntu wsl environment
sudo apt update && sudo apt install -y git
cd HolmesGeo
nano install.sh # paste your maxmind creds and VT API key.
chmod +x install.sh
./install.sh
```

## [📃] Holmes Geo Capabilities

- Extract IP addresses from Apache log files.
- Extract IP addresses from CSV files.
- Read IP addresses from stdin or text files.
- Get geographic and network information for IP addresses.
- Generate reports in CSV and Excel formats.

## [✅] Holmes Geo Basic Usage

> [!NOTE]
> Holmes Geo can be run in several ways, note that the current directory for this example is at /HolmesGeo/

> ### Command Line Interface

```bash
# Using the run script
./chk.sh [OPTIONS]

# Or directly with Python
source venv/bin/python
python3 -m holmesMod.main [OPTIONS]
```

## [🧠] Command Line Options

| Option | Description |
|--------|-------------|
| `--apache FILE` | Extract IPs from an Apache log file |
| `--csv FILE` | Extract IPs from a CSV file |
| `--check FILE` | Check IPs from a text file (one IP per line) |
| `--column NAME` | Specify column name for IP addresses in CSV mode |

## [✏️] Usage Examples

> ### Extract IPs from Apache Log File

```bash
./chk.sh --apache samples/sample_log.txt
python3 -m holmesMod.main --apache apache.log
```

This extracts all IP addresses from the Apache log file and checks their geolocation and network information.

> ### Extract IPs from CSV File

```bash
# Extract from all columns
./chk.sh --csv samples/sample.csv
python3 -m holmesMod.main --csv file.csv

# Extract from a specific column
./chk.sh --csv samples/sample.csv --column ip_address
python3 -m holmesMod.main --csv file.csv --column source_ip
```

> ### Check IPs from a Text File

```bash
./chk.sh --check samples/iplist.txt.txt
python3 -m holmesMod.main --check list_ip.txt
```

> ### Pipe IPs Directly to the Tool

```bash
echo "8.8.8.8" | ./chk.sh
echo -e "8.8.8.8\n37.252.185.229" | ./chk.sh
cat samples/iplist.txt| ./chk.sh
cat ip.txt | python3 -m holmesMod.main
```

> ### To Perform Additional Certificate and Registrar Lookup

```bash
python3 -m holmesMod.main --check list_ip.txt --virtot
python3 -m holmesMod.main --apache apache.log --virtot
python3 -m holmesMod.main --csv file.csv --virtot
python3 -m holmesMod.main --csv file.csv --column source_ip --virtot
./chk.sh --check samples/iplist.txt.txt --virtot
./chk.sh --apache samples/sample_log.txt --virtot
./chk.sh --csv samples/sample.csv --virtot
echo "8.8.8.8" | ./chk.sh --virtot
```

> ### To Disable Reverse DNS Check

```bash
python3 -m holmesMod.main --check list_ip.txt --no-rdns
cat ip.txt | python3 -m holmesMod.main --no-rdns
./chk.sh --check samples/iplist.txt --no-rdns
```

> ### To Disable Output Conversion to CSV & XLSX files.

```bash
python3 -m holmesMod.main --check list_ip.txt --no-output
./chk.sh --check samples/iplist.txt --no-output
```

> ### Graphical User Interface

```bash
./run_gui.sh
```

## [❓] Output

The tool generates two output files in the `results` directory:

1. A CSV file containing the following information for each IP:
- IP Address
- IP Category
- City
- City Latitude
- City Longitude
- Country
- Country Code
- Continent
- ASN Number
- ASN Organization
- Network
- Reverse DNS
- Certificate CN 
- Domain Registrar URL
- User Agent

2. An Excel (XLSX) file with the same information, formatted for better readability.

## [📝] Working with the Results

> [!NOTE]
> **The results are saved in the `holmesMod/results` directory. Each run creates new files with names based on the input source.**

For stdin input:
```
stdin_YYYYMMDD_HHMMSS.csv
stdin_YYYYMMDD_HHMMSS.xlsx
```

For file input:
```
filename_ipinfo.csv
filename_ipinfo.xlsx
```

If a file with the same name already exists, a versioned filename is created:
```
filename_ipinfo_v1.csv
filename_ipinfo_v1.xlsx
```

## [⛓️] Troubleshooting

> [!TIP]
> ### Database Issues  
> If you receive database-related errors, kindly make sure these things.

1. The GeoIP databases are correctly installed:
   
```bash
ls -la holmesMod/db/
```

2. Run the installation script to update databases:
   
```bash
./install.sh
```


> [!TIP]
> ### Permission Issues  
> If you encounter permission issues, run the following commands to fix the permissions for the database files and results directory.


```bash
# Fix permissions for database files
sudo chown -R $USER:$USER holmesMod/db/
chmod 644 holmesMod/db/*.mmdb

# Fix permissions for results directory
chmod -R 755 holmesMod/results/
```

---

## Demo for Holmes Vision & Holmes Geo

|Holmes Vision & Report Result|
|:---------:|
|<img src="assets/arte-dem.gif" width="500"> |
|<img src="assets/Arte-Report.gif" width="500">|

|Holmes Geo & Report Result|
|:--------:|
|<img src="assets/hmgeo-demo.gif" width="500">|
|<img src="assets/hmge-report.gif" width="500">|




## Authors

- [Mark Rizal Tholib](https://github.com/rizal2010)
- [Nicolas Saputra Gunawan](https://github.com/jon-brandy)
