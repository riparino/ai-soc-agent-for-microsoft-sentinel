"""Catalog of KQL hunts the triage agent / MCP server run for an incident.

Each hunt names the Log Analytics table(s) it needs and the indicator kinds it
pivots on. The hunting service picks the hunts whose tables the workspace actually
ingests (see ``KQLRunner.list_tables``) and whose indicators the incident has, then
renders the KQL with the incident's values bound as ``dynamic`` arrays.

Table families covered: Entra ID sign-in / audit / risk (SigninLogs,
AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs,
AADManagedIdentitySignInLogs, AuditLogs, AADRiskyUsers, AADUserRiskEvents,
AADRiskyServicePrincipals, AADServicePrincipalRiskEvents); Defender XDR advanced
hunting schema as ingested into Sentinel (Device*, IdentityLogonEvents, EmailEvents,
EmailUrlInfo, CloudAppEvents); Azure control plane / resource logs (AzureActivity,
AzureDiagnostics); classic security logs (SecurityEvent, Syslog, CommonSecurityLog,
OfficeActivity); alert correlation (SecurityAlert) and threat intelligence
(ThreatIntelligenceIndicator, ThreatIntelIndicators).

Templates use ``string.Template`` (``$name``) so KQL braces stay literal. An empty
indicator list is rendered as a sentinel value that can never match, which keeps
``in~`` / ``has_any`` valid.
"""
from __future__ import annotations

from dataclasses import dataclass
from string import Template
from typing import Any

from app.services.indicators import account_short_names, dedupe, host_short_names, url_domains

NEVER_MATCH = "__no_indicator__"
INDICATOR_KINDS = (
    "accounts", "ips", "hosts", "file_hashes", "urls", "azure_resources", "processes", "cloud_apps", "mailboxes",
)
FAMILIES = ("entra-id", "defender-xdr", "azure", "security-logs", "alerts", "threat-intel")


@dataclass(frozen=True)
class Hunt:
    id: str
    title: str
    family: str
    tables: tuple[str, ...]          # every table must be ingested for the hunt to run
    needs: tuple[str, ...]           # any of these indicator kinds present -> applicable
    window_hours: int
    purpose: str
    kql: str

    def applicable(self, indicators: dict[str, Any]) -> bool:
        return any(indicators.get(k) for k in self.needs)

    def missing_tables(self, available: set[str] | None) -> list[str]:
        if available is None:
            return []
        return [t for t in self.tables if t.lower() not in available]

    def render(self, context: dict[str, str]) -> str:
        return Template(self.kql).substitute(context).strip()


def kql_string(value: Any) -> str:
    s = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", " ")
    return f'"{s}"'


def kql_array(values: list[Any], *, max_len: int = 200, max_items: int = 100) -> str:
    cleaned = [str(v).strip()[:max_len] for v in values if v is not None and str(v).strip()]
    cleaned = dedupe(cleaned)[:max_items] or [NEVER_MATCH]
    return "dynamic([" + ", ".join(kql_string(v) for v in cleaned) + "])"


def window_literal(hours: int) -> str:
    return f"{hours // 24}d" if hours % 24 == 0 and hours >= 24 else f"{hours}h"


def build_context(indicators: dict[str, Any], window_hours: int) -> dict[str, str]:
    accounts = [str(a).lower() for a in indicators.get("accounts") or []]
    hosts = list(indicators.get("hosts") or [])
    urls = list(indicators.get("urls") or [])
    ips = list(indicators.get("ips") or [])
    hashes = list(indicators.get("file_hashes") or [])
    domains = url_domains(urls)
    mailboxes = [str(m).lower() for m in indicators.get("mailboxes") or []]
    processes = [p for p in indicators.get("processes") or [] if len(str(p)) >= 4]
    terms = dedupe(accounts + ips + host_short_names(hosts) + hashes + domains + mailboxes)
    return {
        "accounts": kql_array(accounts),
        "account_names": kql_array(account_short_names(accounts)),
        "ips": kql_array(ips),
        "hosts": kql_array(hosts),
        "host_names": kql_array(host_short_names(hosts)),
        "file_hashes": kql_array(hashes),
        "urls": kql_array(urls, max_len=500),
        "domains": kql_array(domains),
        "azure_resources": kql_array(indicators.get("azure_resources") or [], max_len=500),
        "processes": kql_array(processes, max_len=300),
        "cloud_apps": kql_array(indicators.get("cloud_apps") or []),
        "mailboxes": kql_array(mailboxes),
        "mailboxes_and_accounts": kql_array(dedupe(mailboxes + accounts)),
        "all_terms": kql_array(terms),
        "ioc_values": kql_array(dedupe(ips + urls + domains + hashes), max_len=500),
        "window": window_literal(window_hours),
    }


D, H = 24, 1
HUNTS: tuple[Hunt, ...] = (
    # ------------------------------------------------------------ Entra ID
    Hunt("signin_baseline", "Interactive sign-in baseline for the incident accounts", "entra-id",
         ("SigninLogs",), ("accounts",), 7 * D,
         "Volume, success/failure, distinct IPs, countries, apps, MFA and risk for each account, and how many sign-ins came from the incident IPs.",
         """let accounts = $accounts; let ips = $ips;
SigninLogs
| where TimeGenerated > ago($window)
| where UserPrincipalName in~ (accounts)
| summarize Attempts=count(), Success=countif(ResultType == 0), Failed=countif(ResultType != 0),
    DistinctIPs=dcount(IPAddress), IPs=make_set(IPAddress, 20), Countries=make_set(tostring(LocationDetails.countryOrRegion), 10),
    Apps=make_set(AppDisplayName, 15), RiskLevels=make_set(RiskLevelDuringSignIn, 5),
    FromIncidentIPs=countif(IPAddress in (ips)), MFA=countif(AuthenticationRequirement == "multiFactorAuthentication"),
    FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by UserPrincipalName"""),
    Hunt("signin_from_incident_ips", "Everyone who signed in from the incident IPs", "entra-id",
         ("SigninLogs",), ("ips",), 14 * D,
         "Spread of a suspicious source IP across the tenant: which users, apps and result codes it produced (password spray / token replay).",
         """let ips = $ips;
SigninLogs
| where TimeGenerated > ago($window)
| where IPAddress in (ips)
| summarize Attempts=count(), Success=countif(ResultType == 0), DistinctUsers=dcount(UserPrincipalName), Users=make_set(UserPrincipalName, 25),
    Apps=make_set(AppDisplayName, 10), ResultTypes=make_set(ResultType, 10), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by IPAddress"""),
    Hunt("noninteractive_signins", "Non-interactive (token) sign-ins for the accounts / from the IPs", "entra-id",
         ("AADNonInteractiveUserSignInLogs",), ("accounts", "ips"), 7 * D,
         "Refresh-token and background sign-ins: new IPs or countries here with no matching interactive sign-in suggest token theft / replay.",
         """let accounts = $accounts; let ips = $ips;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago($window)
| where UserPrincipalName in~ (accounts) or IPAddress in (ips)
| summarize Events=count(), Failed=countif(ResultType != 0), IPs=make_set(IPAddress, 20), Apps=make_set(AppDisplayName, 15),
    Resources=make_set(ResourceDisplayName, 15), Countries=make_set(tostring(LocationDetails.countryOrRegion), 10),
    FromIncidentIPs=countif(IPAddress in (ips)), LastSeen=max(TimeGenerated) by UserPrincipalName"""),
    Hunt("service_principal_signins", "Service principal sign-ins from the incident IPs / for the incident apps", "entra-id",
         ("AADServicePrincipalSignInLogs",), ("ips", "cloud_apps"), 7 * D,
         "Workload identities authenticating from attacker infrastructure, or the incident's application signing in and to which resources.",
         """let ips = $ips; let apps = $cloud_apps;
AADServicePrincipalSignInLogs
| where TimeGenerated > ago($window)
| where IPAddress in (ips) or ServicePrincipalName in~ (apps) or AppId in~ (apps)
| summarize Events=count(), Failed=countif(ResultType != 0), IPs=make_set(IPAddress, 20), Resources=make_set(ResourceDisplayName, 15),
    LastSeen=max(TimeGenerated) by ServicePrincipalName, AppId"""),
    Hunt("managed_identity_signins", "Managed identity sign-ins from the incident IPs", "entra-id",
         ("AADManagedIdentitySignInLogs",), ("ips",), 7 * D,
         "Managed identities normally authenticate from Azure ranges; a match on an incident IP is a strong signal of a compromised resource.",
         """let ips = $ips;
AADManagedIdentitySignInLogs
| where TimeGenerated > ago($window)
| where IPAddress in (ips)
| summarize Events=count(), Resources=make_set(ResourceDisplayName, 15), LastSeen=max(TimeGenerated) by ServicePrincipalName, ServicePrincipalId"""),
    Hunt("risky_users", "Identity Protection risk state of the accounts", "entra-id",
         ("AADRiskyUsers",), ("accounts",), 90 * D,
         "Current user risk level / state / detail from Entra ID Protection.",
         """let accounts = $accounts;
AADRiskyUsers
| where TimeGenerated > ago($window)
| where UserPrincipalName in~ (accounts)
| summarize arg_max(TimeGenerated, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime) by UserPrincipalName"""),
    Hunt("user_risk_detections", "Identity Protection risk detections for the accounts / IPs", "entra-id",
         ("AADUserRiskEvents",), ("accounts", "ips"), 30 * D,
         "Detections such as anonymous IP, unfamiliar sign-in properties, leaked credentials or impossible travel, with their risk state.",
         """let accounts = $accounts; let ips = $ips;
AADUserRiskEvents
| where TimeGenerated > ago($window)
| where UserPrincipalName in~ (accounts) or IpAddress in (ips)
| summarize Detections=count(), Types=make_set(RiskEventType, 10), Levels=make_set(RiskLevel, 5), States=make_set(RiskState, 5),
    IPs=make_set(IpAddress, 10), Sources=make_set(Source, 5), LastSeen=max(TimeGenerated) by UserPrincipalName"""),
    Hunt("risky_service_principals", "Identity Protection risk state of the incident applications", "entra-id",
         ("AADRiskyServicePrincipals",), ("cloud_apps",), 90 * D,
         "Workload identity risk for the application / service principal entities.",
         """let apps = $cloud_apps;
AADRiskyServicePrincipals
| where TimeGenerated > ago($window)
| where ServicePrincipalName in~ (apps) or AppId in~ (apps) or ServicePrincipalId in~ (apps)
| summarize arg_max(TimeGenerated, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime) by ServicePrincipalName, AppId"""),
    Hunt("service_principal_risk_detections", "Workload identity risk detections for the apps / IPs", "entra-id",
         ("AADServicePrincipalRiskEvents",), ("cloud_apps", "ips"), 30 * D,
         "Service principal risk detections (suspicious sign-ins, leaked credentials, anomalous API traffic).",
         """let apps = $cloud_apps; let ips = $ips;
AADServicePrincipalRiskEvents
| where TimeGenerated > ago($window)
| where ServicePrincipalName in~ (apps) or AppId in~ (apps) or IpAddress in (ips)
| summarize Detections=count(), Types=make_set(RiskEventType, 10), Levels=make_set(RiskLevel, 5), IPs=make_set(IpAddress, 10),
    LastSeen=max(TimeGenerated) by ServicePrincipalName, AppId"""),
    Hunt("directory_audit", "Directory changes by or against the accounts", "entra-id",
         ("AuditLogs",), ("accounts", "ips"), 30 * D,
         "Role assignments, MFA method changes, app consents, password resets and other directory operations initiated by or targeting the accounts.",
         """let accounts = $accounts; let ips = $ips;
AuditLogs
| where TimeGenerated > ago($window)
| extend Initiator = tolower(coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))),
    InitiatorIP = tostring(InitiatedBy.user.ipAddress),
    Target = tolower(tostring(TargetResources[0].userPrincipalName)), TargetName = tostring(TargetResources[0].displayName)
| where Initiator in~ (accounts) or Target in~ (accounts) or InitiatorIP in (ips)
| summarize Count=count(), Results=make_set(Result, 3), Targets=make_set(coalesce(Target, TargetName), 10), Initiators=make_set(Initiator, 10),
    LastSeen=max(TimeGenerated) by OperationName, Category
| order by LastSeen desc
| take 50"""),
    # -------------------------------------------------------- Defender XDR
    Hunt("device_logons", "Endpoint logons for the accounts / hosts / remote IPs", "defender-xdr",
         ("DeviceLogonEvents",), ("accounts", "hosts", "ips"), 7 * D,
         "Interactive, network and RDP logons on Defender-onboarded devices, failures, local-admin logons and the remote IPs involved (lateral movement).",
         """let accounts = $accounts; let names = $account_names; let hosts = $host_names; let ips = $ips;
DeviceLogonEvents
| where TimeGenerated > ago($window)
| where AccountUpn in~ (accounts) or AccountName in~ (names) or DeviceName has_any (hosts) or RemoteIP in (ips)
| summarize Logons=count(), Failed=countif(ActionType == "LogonFailed"), Types=make_set(LogonType, 6), RemoteIPs=make_set(RemoteIP, 15),
    Accounts=make_set(AccountName, 15), LocalAdmin=max(toint(IsLocalAdmin)), LastSeen=max(TimeGenerated) by DeviceName, AccountUpn
| order by Failed desc, Logons desc
| take 50"""),
    Hunt("device_suspicious_processes", "Suspicious process executions on the hosts / by the accounts", "defender-xdr",
         ("DeviceProcessEvents",), ("hosts", "accounts", "processes"), 7 * D,
         "LOLBins, encoded / download-cradle command lines, Office-spawned children and the incident's own process entities, with SHA256 for pivoting.",
         """let hosts = $host_names; let names = $account_names; let accounts = $accounts; let procs = $processes;
DeviceProcessEvents
| where TimeGenerated > ago($window)
| where DeviceName has_any (hosts) or AccountUpn in~ (accounts) or AccountName in~ (names)
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "msiexec.exe", "wmic.exe", "schtasks.exe", "net.exe", "net1.exe", "whoami.exe", "nltest.exe", "psexec.exe", "psexesvc.exe",
        "curl.exe", "ntdsutil.exe", "vssadmin.exe", "reg.exe", "rclone.exe", "7z.exe", "procdump.exe")
    or ProcessCommandLine has_any ("-enc", "-encodedcommand", "frombase64string", "downloadstring", "downloadfile", "iex ", "invoke-expression",
        "-nop", "bypass", "hidden", "mimikatz", "lsass", "sekurlsa")
    or ProcessCommandLine has_any (procs)
    or InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "acrord32.exe", "onenote.exe", "msedge.exe", "chrome.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
| order by TimeGenerated desc
| take 50"""),
    Hunt("device_network", "Endpoint network connections to the incident IPs / domains", "defender-xdr",
         ("DeviceNetworkEvents",), ("ips", "urls", "hosts"), 14 * D,
         "Which devices and processes talked to the suspected C2 / phishing infrastructure, plus the public destinations of the incident hosts.",
         """let ips = $ips; let domains = $domains; let hosts = $host_names;
DeviceNetworkEvents
| where TimeGenerated > ago($window)
| where RemoteIP in (ips) or RemoteUrl has_any (domains) or (DeviceName has_any (hosts) and RemoteIPType == "Public")
| summarize Connections=count(), DeviceCount=dcount(DeviceName), Devices=make_set(DeviceName, 15), Ports=make_set(RemotePort, 10),
    Processes=make_set(InitiatingProcessFileName, 10), Actions=make_set(ActionType, 5), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by RemoteIP, RemoteUrl
| order by Connections desc
| take 50"""),
    Hunt("device_file_hashes", "Files matching the incident hashes across the fleet", "defender-xdr",
         ("DeviceFileEvents",), ("file_hashes",), 30 * D,
         "Where the malicious file landed (devices, paths, names) and when it was first seen.",
         """let hashes = $file_hashes;
DeviceFileEvents
| where TimeGenerated > ago($window)
| where SHA256 in~ (hashes) or SHA1 in~ (hashes) or MD5 in~ (hashes)
| summarize Events=count(), DeviceCount=dcount(DeviceName), Devices=make_set(DeviceName, 20), FileNames=make_set(FileName, 10), Folders=make_set(FolderPath, 10),
    Actions=make_set(ActionType, 5), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by SHA256"""),
    Hunt("device_hash_executions", "Executions of the incident hashes across the fleet", "defender-xdr",
         ("DeviceProcessEvents",), ("file_hashes",), 30 * D,
         "Devices and accounts that ran a binary with one of the incident hashes, with the command lines used.",
         """let hashes = $file_hashes;
DeviceProcessEvents
| where TimeGenerated > ago($window)
| where SHA256 in~ (hashes) or SHA1 in~ (hashes) or MD5 in~ (hashes)
| summarize Executions=count(), Devices=make_set(DeviceName, 20), Accounts=make_set(AccountName, 10), CommandLines=make_set(ProcessCommandLine, 5),
    FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by SHA256, FileName"""),
    Hunt("device_inventory", "Device inventory for the incident hosts", "defender-xdr",
         ("DeviceInfo",), ("hosts",), 7 * D,
         "OS, onboarding/sensor state, join type, exposure level, public IP and logged-on users for the hosts.",
         """let hosts = $host_names;
DeviceInfo
| where TimeGenerated > ago($window)
| where DeviceName has_any (hosts)
| summarize arg_max(TimeGenerated, OSPlatform, OSVersionInfo, PublicIP, OnboardingStatus, DeviceType, JoinType, MachineGroup, ExposureLevel, LoggedOnUsers) by DeviceName, DeviceId"""),
    Hunt("device_defensive_events", "Antivirus / ASR / tampering / exploit-guard events on the hosts", "defender-xdr",
         ("DeviceEvents",), ("hosts", "accounts"), 7 * D,
         "Defender protections that fired on the hosts or for the accounts: AV detections, attack-surface-reduction blocks, tamper attempts, SmartScreen, credential access.",
         """let hosts = $host_names; let names = $account_names;
DeviceEvents
| where TimeGenerated > ago($window)
| where DeviceName has_any (hosts) or AccountName in~ (names) or InitiatingProcessAccountName in~ (names)
| where ActionType has_any ("Antivirus", "Asr", "Tamper", "Exploit", "SmartScreen", "ControlledFolder", "NetworkProtection", "PowerShellCommand",
        "ScheduledTask", "ServiceInstalled", "UsbDrive", "LdapSearch", "Ntds", "Dpapi", "NamedPipe", "Shadow")
| summarize Count=count(), Devices=make_set(DeviceName, 10), Files=make_set(FileName, 10), Processes=make_set(InitiatingProcessFileName, 10),
    FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by ActionType
| order by Count desc
| take 50"""),
    Hunt("device_registry_persistence", "Registry persistence changes on the hosts", "defender-xdr",
         ("DeviceRegistryEvents",), ("hosts",), 7 * D,
         "Run / RunOnce keys, services, Winlogon, IFEO and Defender policy keys modified on the hosts, with the responsible process.",
         """let hosts = $host_names;
DeviceRegistryEvents
| where TimeGenerated > ago($window)
| where DeviceName has_any (hosts)
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\Services\", @"\Winlogon", @"\Image File Execution Options",
        @"\Explorer\Shell Folders", @"\Policies\Microsoft\Windows Defender")
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
| take 50"""),
    Hunt("identity_logons", "On-premises AD / Defender for Identity logons for the accounts / IPs", "defender-xdr",
         ("IdentityLogonEvents",), ("accounts", "ips"), 7 * D,
         "Kerberos / NTLM / LDAP logons seen by Defender for Identity: source devices, targets, failures and reasons.",
         """let accounts = $accounts; let names = $account_names; let ips = $ips;
IdentityLogonEvents
| where TimeGenerated > ago($window)
| where AccountUpn in~ (accounts) or AccountName in~ (names) or IPAddress in (ips)
| summarize Logons=count(), Failed=countif(ActionType == "LogonFailed"), Protocols=make_set(Protocol, 6), Devices=make_set(DeviceName, 15),
    Targets=make_set(TargetDeviceName, 15), IPs=make_set(IPAddress, 15), Reasons=make_set(FailureReason, 5), LastSeen=max(TimeGenerated) by AccountUpn"""),
    Hunt("email_events", "Email to / from the incident mailboxes and sender domains", "defender-xdr",
         ("EmailEvents",), ("accounts", "mailboxes", "urls"), 14 * D,
         "Messages delivered to the users (or from the incident domains): threat verdicts, delivery action/location, attachments and URL counts — flagged mail first.",
         """let rcpts = $mailboxes_and_accounts; let domains = $domains;
EmailEvents
| where TimeGenerated > ago($window)
| where RecipientEmailAddress in~ (rcpts) or SenderFromAddress in~ (rcpts) or SenderFromDomain has_any (domains)
| extend Flagged = isnotempty(ThreatTypes) or DeliveryAction != "Delivered"
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, SenderIPv4, Subject, ThreatTypes, ThreatNames, DeliveryAction, DeliveryLocation,
    AttachmentCount, UrlCount, NetworkMessageId, Flagged
| order by Flagged desc, TimeGenerated desc
| take 50"""),
    Hunt("email_urls", "Emails carrying the incident URLs / domains", "defender-xdr",
         ("EmailUrlInfo",), ("urls",), 14 * D,
         "How many messages carried the phishing URL / domain and which exact URLs were used.",
         """let domains = $domains; let urls = $urls;
EmailUrlInfo
| where TimeGenerated > ago($window)
| where UrlDomain has_any (domains) or Url has_any (urls)
| summarize Messages=dcount(NetworkMessageId), Urls=make_set(Url, 10), LastSeen=max(TimeGenerated) by UrlDomain"""),
    Hunt("cloud_app_activity", "Cloud app (Defender for Cloud Apps) activity for the accounts / IPs", "defender-xdr",
         ("CloudAppEvents",), ("accounts", "ips"), 7 * D,
         "SaaS activity by the accounts or from the incident IPs: mass download, inbox rules, sharing, admin operations, with ISP / country context.",
         """let accounts = $accounts; let ips = $ips;
CloudAppEvents
| where TimeGenerated > ago($window)
| where AccountDisplayName in~ (accounts) or AccountObjectId in~ (accounts) or tolower(tostring(RawEventData.UserId)) in~ (accounts) or IPAddress in (ips)
| summarize Count=count(), Apps=make_set(Application, 10), IPs=make_set(IPAddress, 10), Countries=make_set(CountryCode, 5), ISPs=make_set(ISP, 5),
    LastSeen=max(TimeGenerated) by ActionType, AccountDisplayName
| order by Count desc
| take 50"""),
    # ---------------------------------------------------------------- Azure
    Hunt("azure_activity", "Azure control-plane operations by the accounts / IPs / on the resources", "azure",
         ("AzureActivity",), ("accounts", "ips", "azure_resources"), 7 * D,
         "ARM operations (role assignments, key listing, VM run-command, resource changes) with callers, IPs, status and resources.",
         """let accounts = $accounts; let ips = $ips; let res = $azure_resources;
AzureActivity
| where TimeGenerated > ago($window)
| where Caller in~ (accounts) or CallerIpAddress in (ips) or _ResourceId has_any (res) or ResourceId has_any (res)
| summarize Count=count(), Statuses=make_set(ActivityStatusValue, 4), Callers=make_set(Caller, 10), IPs=make_set(CallerIpAddress, 10),
    Resources=make_set(_ResourceId, 10), LastSeen=max(TimeGenerated) by OperationNameValue
| order by LastSeen desc
| take 50"""),
    Hunt("azure_resource_logs", "Azure resource logs (AzureDiagnostics) from the incident IPs / for the resources", "azure",
         ("AzureDiagnostics",), ("ips", "azure_resources"), 7 * D,
         "Key Vault, Firewall, SQL, App Gateway, storage and other resource logs where the client IP is an incident IP or the resource is an incident entity.",
         """let ips = $ips; let res = $azure_resources;
AzureDiagnostics
| where TimeGenerated > ago($window)
| extend ClientIP = coalesce(column_ifexists("CallerIPAddress", ""), column_ifexists("clientIp_s", ""), column_ifexists("clientIP_s", ""),
    column_ifexists("client_ip_s", ""), column_ifexists("callerIpAddress_s", ""))
| extend ClientIP = tostring(split(ClientIP, ":")[0])
| where ClientIP in (ips) or ResourceId has_any (res) or _ResourceId has_any (res)
| summarize Count=count(), Resources=make_set(ResourceId, 10), Results=make_set(column_ifexists("ResultType", ""), 5), IPs=make_set(ClientIP, 10),
    LastSeen=max(TimeGenerated) by ResourceType, Category, OperationName
| order by Count desc
| take 50"""),
    # -------------------------------------------------------- security logs
    Hunt("windows_security_events", "Windows Security events for the accounts / hosts / IPs", "security-logs",
         ("SecurityEvent",), ("accounts", "hosts", "ips"), 7 * D,
         "Logon success/failure, explicit-credential use, special privileges, process creation, service install, account/group changes and log clearing.",
         """let names = $account_names; let hosts = $host_names; let ips = $ips;
SecurityEvent
| where TimeGenerated > ago($window)
| where EventID in (4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4722, 4724, 4728, 4732, 4756, 4768, 4769, 4771, 4776, 1102, 7045)
| where Account has_any (names) or TargetUserName in~ (names) or SubjectUserName in~ (names) or Computer has_any (hosts) or IpAddress in (ips)
| summarize Count=count(), Accounts=make_set(TargetUserName, 10), Computers=make_set(Computer, 10), IPs=make_set(IpAddress, 10), LogonTypes=make_set(LogonType, 6),
    LastSeen=max(TimeGenerated) by EventID, Activity
| order by Count desc
| take 50"""),
    Hunt("office_activity", "Microsoft 365 activity for the accounts / mailboxes / IPs", "security-logs",
         ("OfficeActivity",), ("accounts", "mailboxes", "ips"), 7 * D,
         "Exchange / SharePoint / Teams operations: inbox rules, mailbox delegation, file downloads and sharing by the users or from the incident IPs.",
         """let accounts = $mailboxes_and_accounts; let ips = $ips;
OfficeActivity
| where TimeGenerated > ago($window)
| where UserId in~ (accounts) or ClientIP has_any (ips) or Client_IPAddress has_any (ips)
| summarize Count=count(), Results=make_set(ResultStatus, 3), IPs=make_set(ClientIP, 10), Items=make_set(OfficeObjectId, 5), Workloads=make_set(OfficeWorkload, 5),
    LastSeen=max(TimeGenerated) by Operation, UserId
| order by Count desc
| take 50"""),
    Hunt("firewall_proxy_traffic", "Firewall / proxy traffic to or from the incident IPs and domains", "security-logs",
         ("CommonSecurityLog",), ("ips", "urls", "hosts"), 14 * D,
         "CEF sources (Palo Alto, Fortinet, Check Point, Zscaler…): sessions, bytes, actions and ports involving the incident infrastructure or hosts.",
         """let ips = $ips; let domains = $domains; let hosts = $host_names;
CommonSecurityLog
| where TimeGenerated > ago($window)
| where DestinationIP in (ips) or SourceIP in (ips) or RequestURL has_any (domains) or DestinationHostName has_any (domains) or SourceHostName has_any (hosts)
| summarize Events=count(), Bytes=sum(SentBytes + ReceivedBytes), Actions=make_set(DeviceAction, 5), Ports=make_set(DestinationPort, 10), Vendors=make_set(DeviceVendor, 3),
    FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by SourceIP, DestinationIP
| order by Events desc
| take 50"""),
    Hunt("linux_auth", "Linux authentication (Syslog auth) for the accounts / hosts / IPs", "security-logs",
         ("Syslog",), ("accounts", "hosts", "ips"), 7 * D,
         "sshd / sudo / su activity: accepted vs failed logons per host and process.",
         """let names = $account_names; let hosts = $host_names; let ips = $ips;
Syslog
| where TimeGenerated > ago($window)
| where Facility in ("auth", "authpriv") or ProcessName in ("sshd", "sudo", "su")
| where SyslogMessage has_any (names) or Computer has_any (hosts) or SyslogMessage has_any (ips)
| summarize Count=count(), Failed=countif(SyslogMessage has_any ("Failed", "failure", "invalid")), Accepted=countif(SyslogMessage has "Accepted"),
    LastSeen=max(TimeGenerated) by ProcessName, Computer
| order by Count desc
| take 50"""),
    # ---------------------------------------------------------------- alerts
    Hunt("related_alerts", "Other alerts mentioning the incident entities", "alerts",
         ("SecurityAlert",), INDICATOR_KINDS, 14 * D,
         "Cross-product alert correlation: every Sentinel / Defender alert in the window whose entities or description mention the same accounts, IPs, hosts, hashes or domains.",
         """let terms = $all_terms;
SecurityAlert
| where TimeGenerated > ago($window)
| where Entities has_any (terms) or ExtendedProperties has_any (terms) or Description has_any (terms)
| summarize Alerts=count(), Severities=make_set(AlertSeverity, 4), Products=make_set(ProductName, 5), Tactics=make_set(Tactics, 8),
    FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by AlertName
| order by Alerts desc
| take 50"""),
    # ---------------------------------------------------------- threat intel
    Hunt("threat_intel_indicators", "Threat-intelligence indicators matching the incident IOCs (ThreatIntelIndicators)", "threat-intel",
         ("ThreatIntelIndicators",), ("ips", "urls", "file_hashes"), 90 * D,
         "Active STIX indicators in the workspace's current TI table that match the incident IPs, URLs, domains or hashes.",
         """let terms = $ioc_values;
ThreatIntelIndicators
| where TimeGenerated > ago($window)
| where IsActive == true and ValidUntil > now()
| where ObservableValue in~ (terms)
| summarize arg_max(TimeGenerated, ObservableKey, Confidence, SourceSystem, ValidUntil, Tags, Description=tostring(Data.description)) by Id
| take 50"""),
    Hunt("threat_intel_indicators_legacy", "Threat-intelligence indicators matching the incident IOCs (ThreatIntelligenceIndicator)", "threat-intel",
         ("ThreatIntelligenceIndicator",), ("ips", "urls", "file_hashes"), 90 * D,
         "Active indicators in the legacy TI table (TAXII / TI platforms / Defender TI) that match the incident IPs, URLs, domains or hashes.",
         """let ips = $ips; let urls = $urls; let domains = $domains; let hashes = $file_hashes;
ThreatIntelligenceIndicator
| where TimeGenerated > ago($window)
| where Active == true
| where NetworkIP in (ips) or NetworkSourceIP in (ips) or NetworkDestinationIP in (ips) or Url has_any (urls) or DomainName has_any (domains) or FileHashValue in~ (hashes)
| summarize arg_max(TimeGenerated, ThreatType, ConfidenceScore, Description, SourceSystem, ExpirationDateTime, Tags) by IndicatorId
| take 50"""),
)

HUNTS_BY_ID: dict[str, Hunt] = {h.id: h for h in HUNTS}
ALL_TABLES: tuple[str, ...] = tuple(sorted({t for h in HUNTS for t in h.tables}))


def catalog_summary() -> list[dict[str, Any]]:
    return [
        {"id": h.id, "title": h.title, "family": h.family, "tables": list(h.tables), "needs": list(h.needs),
         "window_hours": h.window_hours, "purpose": h.purpose}
        for h in HUNTS
    ]
