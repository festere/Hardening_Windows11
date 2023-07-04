![](https://img.shields.io/badge/hardening-red?style=for-the-badge)
![](https://img.shields.io/badge/windows-blue?style=for-the-badge)

<br>

# Table of contents
1. [Disclaimer](#Disclaimer)
2. [Description](#Description)
3. [Functionalities](#Functionalities)
    1. [Security](#Security)
    2. [Optimisation](#Optimisation)
4. [Installation](#Installation)
   
<br>
<br>
<br>
<br>

# <a name="Disclaimer">Disclaimer:</a>
<span style="color:red">Before using any of our application(s) and/or sevice(s), please ensure that you have read and understood our license, terms of use (in the license), and copyright policy (in the license). By using our application(s) and/or sevice(s), you agree to comply with all applicable laws and regulations, and to be bound by our license, terms of use, and copyright policy. If you do not agree with any part of these documents, you must not use our app or services. Please note that our license, terms of use, and copyright policy are subject to change without notice, and it is your responsibility to periodically review these documents for any updates or changes.</span>

<br>
<br>
<br>
<br>

# <a name="Description">Description:</a>
This tool harden Windows 10 and 11 by improving the security, anonymity and by updating and optimising some drivers.

<br>
<br>
<br>
<br>

# <a name="Functionalities">Functionalities:</a>
1. <a name="Security">Security:</a>
- [x] Restore point creation
- [x] Retain or remove local user administrator rights
- [x] Activate Windows Defender features
- [x] Enable real-time monitoring
- [x] Disable sample submission
- [x] Enable signature verification before scanning
- [x] Enable behavioral monitoring
- [x] Enable IOAV protection
- [x] Enable script analysis
- [x] Enable removable drive analysis
- [x] Enable first-view blocking
- [x] Enable potentially unwanted applications
- [x] Enable archive analysis
- [x] Enable e-mail analysis
- [x] Enable file hash calculation
- [x] Activate intrusion prevention system
- [x] Enable TLS analysis
- [x] Enable SSH analysis
- [x] Activate DNS analysis
- [x] Chasm activation
- [x] Enable controlled access to folders and set to block mode
- [x] Activate network protection and set blocking mode
- [x] Enable sandboxing for Windows Defender
- [x] Set cloud blocking level to High
- [x] Set cloud block expiry time to 1 minute
- [x] Schedule signature updates every 8 hours
- [x] Disable account prompts
- [x] Enable cloud-provided protection
- [x] Prevent all Office applications from creating child processes
- [x] Prevent Office applications from creating executable content
- [x] Prevent Office applications from injecting code into other processes
- [x] Prevent JavaScript or VBScript from launching downloaded executable content
- [x] Prevent Office communication application from creating child processes
- [x] Prevent Adobe Reader from creating child processes
- [x] Block executable content in e-mail client and webmail
- [x] Block execution of potentially obfuscated scripts
- [x] Block Win32 API calls from Office macros
- [x] Block execution of executable files unless they meet prevalence, age or trusted list criteria
- [x] Block theft of Windows Local Security Authority subsystem credentials
- [x] Block process creations from PSExec and WMI commands
- [x] Block unapproved and unsigned processes running from USBs
- [x] Block abuse of vulnerable signed drivers
- [x] Use advanced ransomware protection
- [x] Activate Let Windows apps access the calendar rule
- [x] Let Windows apps access call history rule enabled
- [x] Let Windows apps access contacts rule enabled
- [x] Let Windows apps access email rule enabled
- [x] Let Windows apps access location enabled
- [x] Let Windows apps access messaging enabled
- [x] Let Windows apps access account information rule enabled
- [x] Disable rule Toggle user control on Insider trial versions
- [x] Enable rule Do not display comment notifications
- [x] Enable Inventory Collector rule
- [x] Enable rule Disable Microsoft consumer experiences
- [x] Don't display Windows tips rule activation
- [x] Disable rule Allows Windows Store applications to be developed and installed from an integrated development environment
- [x] Disable rule Allow a Windows application to share application data between users
- [x] Disable location rule activation
- [x] Enable rule Disable location scripting
- [x] Enable rule Allow Microsoft accounts to be optional
- [x] Enable rule Block Windows Store applications with Windows Runtime API access from hosted content
- [x] Disable rule Allow remote server management via WinRM
- [x] Enable HTTP compatibility listener rule disabled
- [x] Enable HTTPS compatibility listener rule disabled
- [x] Disable Allow basic authentication rule
- [x] Disable Allow unencrypted traffic rule
- [x] Don't allow WinRM to store RunAs credentials rule enabled
- [x] Disable rule Do not allow authentication by negotiation
- [x] Disable rule Do not allow Kerberos authentication
- [x] Disable rule Allow CredSSP authentication
- [x] Enable rule Specify enhanced security level for channel link tokens
- [x] Enable rule Prevent computer from joining residential group
- [x] Rule disabling List administrator accounts with elevated privileges
- [x] Enable rule Require approved path for credential entry
- [x] Enable or disable Secure Attention Sequence (SAS) rule
- [x] Enable Windows Error Reporting rule
- [x] Disable Allow Cortana rule
- [x] Disable rule Allow search and allow Cortana to use location
- [x] Don't allow passwords to be saved rule enabled
- [x] Don't allow drive redirection rule enabled
- [x] Activate rule Always ask for password on login
- [x] Activate rule Require secure RPC communications
- [x] Activate rule Set default Autorun behavior
- [x] Enable automatic execution rule
- [x] Enable rule Prohibit autorun for non-volume devices
- [x] Enable Join Microsoft MAPS rule
- [x] Enable rule Scan all downloaded files and attachments
- [x] Disable real-time protection rule
- [x] Disable rule Always install with elevated rights
- [x] Enable Automatic Updates service configuration rule
- [x] Apply UAC restrictions to local accounts on network logons rule enabled
- [x] Disable WDigest Authentication rule (disabling may require KB2871997)
- [x] Enable MSS rule: (DisableSavePassword) Prevent the dial-up password from being saved
- [x] Disable MSS rule: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes
- [x] Enable MSS rule: (Hidden) Hide Computer From the Browse List (not recommended except for highly secure environments)
- [x] Enable MSS rule: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers
- [x] Disable MSS rule: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)
- [x] Enable MSS rule: (SafeDllSearchMode) Enable Safe DLL search mode
- [x] Enable MSS rule: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)
- [x] Enable MSS rule: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)
- [x] Enable MSS rule: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)
- [x] Enable MSS rule: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)
- [x] Enable MSS rule: (KeepAliveTime) How often keep-alive packets are sent in milliseconds
- [x] Enable SSL 2.0 rule on client
- [x] Enable SSL 3.0 rule on client
- [x] Enable TLS 1.0 rule on client
- [x] Activate TLS 1.1 rule on client
- [x] Activate TLS 1.2 rule on client
- [x] Activate TLS 1.3 rule on client
- [x] Activate SSL 2.0 rule on server
- [x] Activate SSL 3.0 rule on server
- [x] Activate TLS 1.0 rule on server
- [x] Enable TLS 1.1 rule on server
- [x] Enable TLS 1.2 rule on server
- [x] Enable TLS 1.3 rule on server
- [x] Enable rule Prevent slideshow activation from lock screen
- [x] Enable rule Prevent lock screen camera activation
- [x] Enable rule Disable Microsoft peer-to-peer network services
- [x] Enable rule Disable multicast name resolution
- [x] Enable rule Disable intelligent multiresident name resolution
- [x] Enable rule Prohibit installation and configuration of a network bridge on your DNS domain network
- [x] Disable Link Layer Topology Discovery Mapper I/O driver rule
- [x] Disable rule Enable responder driver (RSPNDR)
- [x] Enable rule Prohibit connection to domain-less networks when connecting to a network authenticated by its domain
- [x] Activate SSL cipher suite order rule
- [x] Activate Set ISATAP state rule
- [x] Activate Set Teredo status rule
- [x] Activate Set IP-HTTPS state rule
- [x] Disable rule Prevent Windows from automatically connecting to suggested open access points, networks shared by contacts and access points offering paid services
- [x] Disable rule Enable unsecured guest logins
- [x] Disable Windows Connect Now Wizards rule
- [x] Disable rule Configure wireless settings using Windows Connect Now
- [x] Activate CD and DVD rule: deny access at runtime
- [x] Diskette drives rule enabled: deny access at runtime
- [x] Activate removable disks rule: deny access at runtime
- [x] Enable Tape drives: deny access at runtime rule
- [x] Enable RPC endpoint mapper client authentication rule
- [x] Enable rule Limit unauthenticated RPC clients
- [x] Disable rule Configure remote assistance requested
- [x] Activate Ask for password when computer wakes from standby (mains) rule
- [x] Request password when computer wakes from standby (battery-powered) rule enabled
- [x] Disable rule Allow standby states (S1-S3) when computer is in standby mode (on mains)
- [x] Disable rule Allow sleep states (S1-S3) when computer is in sleep mode (battery-operated)
- [x] Enable rule Disable automatic update of root certificates
- [x] Enable rule Disable event viewer "Events.asp" links
- [x] Enable rule Disable "Did you know?" content in Help & Support Center
- [x] Enable rule Disable Microsoft Knowledge Base search in Help & Support Center
- [x] Enable rule Disable Internet Connection Wizard if connection URL refers to Microsoft.com
- [x] Enable rule Disable registration if login URL refers to Microsoft.com
- [x] Enable rule Disable access to all Windows Update features
- [x] Enable rule Disable Search Wizard content file updates
- [x] Enable rule Disable Internet file association service
- [x] Enable rule Disable Windows Network Connectivity Status Indicator active tests
- [x] Enable boot driver initialization strategy rule
- [x] Disable rule Show animation on first connection
- [x] Don't display network selection user interface rule enabled
- [x] Enable rule Do not enumerate logged-in users on domain computers
- [x] Disable rule List local users on domain computers
- [x] Disable application notifications on lock screen rule enabled
- [x] Enable Disable Ad ID rule
- [x] Enable virtualization-based security rule
- [x] Enable toast notifications on lock screen rule
- [x] Enable password-protected screen saver rule
- [x] Enable rule Disable help ratings
- [x] Enable rule Disable help enhancement program
- [x] Activate Disable Windows Online rule
- [x] Enable rule Disable printing via HTTP
- [x] Activate rule Disable printer driver download via HTTP
- [x] Activate rule Disable Internet file association service
- [x] Enable rule Disable download from Internet for Website Publishing and Online Order Wizards via Internet
- [x] Activate rule Disable Order photos in Image Management
- [x] Enable rule Disable Publish to Web option in File Management
- [x] Enable rule Disable Service Enhancement Program for Windows Messenger
- [x] Enable rule Disable handwriting recognition error reporting
- [x] Enable rule Disable handwriting personalization data sharing
- [x] Disable Microsoft Account Login Wizard service (wlidsvc)
- [x] Configure Group Policy Client service (gpsvc)
- [x] Set boot driver initialization strategy to good and unknown
- [x] Record events without blocking unapproved fonts
- [x] Do not display animation on first login
- [x] Do not display network selection user interface
- [x] Do not list logged-in users on computers belonging to a domain
- [x] Disable application notifications on lock screen
- [x] Disable advertising ID
- [x] Enable virtualization-based security
- [x] Disable toast notifications on lock screen
- [x] Password-protected screen saver
- [x] Activate services: "AppIDSvc, gpsvc, EventLog, Netlogon, MpsSvc".
- [x] Encrypt and sign outgoing traffic via secure channel if possible
- [x] Activate SmartScreen
- [x] Enable DontDisplayNetworkSelectionUI
- [x] Discover extensions and cache files
- [x] Disable autoplay from all disks
- [x] Block download optimization from other network devices
- [x] Enlarge log size in Windows Event
- [x] Save command line data in registry (eventid 4688)
- [x] Enable advanced settings
- [x] Enable PowerShell connection
- [x] Enable log details
- [x] Apply limitations to Windows Analytics if enabled
- [x] Apply Windows telemetry only in security mode
- [x] Disable data localization
- [x] Prevent menu startup from providing Internet information and using geolocation
- [x] Disable publication of user activity
- [x] Disable cloud synchronization
- [x] Disable Windows GameDVR
- [x] Disable Microsoft consumer experience to prevent notifications and suggestions of applications to install
- [x] Disable website access to language list
- [x] Enable anti-usurpation for facial recognition
- [x] Disable other cameras when screen is closed
- [x] Prevent Windows voice recognition applications when screen is closed
- [x] Enable Firewall connection
- [x] Blocks all incoming connections to the public profile
- [x] Enable Windows Defender Network Protection
- [x] Blocks connections when programs are not active
- [x] Disabling services: "WpcMonSvc, SharedRealitySvc, Fax, autotimesvc, wisvc, SDRSVC, MixedRealityOpenXRSvc, WalletService, SmsRouter, MapsBroker, PhoneSvc, ScDeviceEnum, TabletInputService, icssvc, edgeupdatem, edgeupdate, MicrosoftEdgeElevationService, RetailDemo, MessagingService, PimIndexMaintenanceSvc, OneSyncSvc, UnistoreSvc, dmwappushservice, diagnosticshub.standardcollector.service, diagsvc, WerSvc, wercplsupport, wlidsvc, NcdAutoSetup, DataCollectionPublishingService, SSDPSRV, dmwapphushservice, DiagTrack, Browser, HomeGroupProvider, p2pimsvc, XblAuthManager, RasAuto, RasMan, p2psvc, upnphost, fdPHost, XblGameSave, ltdsvc, SharedAccess, PNRPsvc, FDResPub, RemoteRegistry, RemoteAccess, WlanSvc, WwanSvc, WinHttpAutoProxySvc, retaildemo, lfsvc, blthserv, AJRouter, WMPNetworkSvc, WSService, wcncsvc, ClickToRunSvc, OneSyncSvc_184354, MapsBroker"

<br>

2. <a name="Optimisation">Optimisation:</a>
- [x] Deleting temporary files
- [x] Installation/update of Microsoft.dotNetFramework
- [x] Install/update Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.34.31931
- [x] Install/update Microsoft Windows Desktop Runtime - 6.0.14 (x64)
- [x] Microsoft Windows Desktop Runtime installation/update - 7.0.3 (x64)
- [x] Microsoft DirectX installation/update
      
<br>
<br>
<br>
<br>

# <a name="Installation">Installation:</a>
1. Download the app
2. Start the tool: ```launcher.cmd```
