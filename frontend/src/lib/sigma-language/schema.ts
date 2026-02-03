/**
 * Sigma Rule Schema
 *
 * Static TypeScript data for Sigma rule autocomplete and documentation.
 * Based on SigmaHQ specifications:
 * - https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md
 * - https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md
 * - https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-taxonomy-appendix.md
 */

export interface SchemaItem {
  key?: string
  value?: string
  name?: string
  keyword?: string
  field?: string
  doc: string
  required?: boolean
  example?: string
}

export const SIGMA_SCHEMA = {
  topLevelKeys: [
    {
      key: 'title',
      doc: 'Brief rule description (max 256 characters)',
      required: true,
      example: 'title: Suspicious PowerShell Download',
    },
    {
      key: 'id',
      doc: 'UUID v4 identifier for the rule',
      required: false,
      example: 'id: 12345678-1234-1234-1234-123456789012',
    },
    {
      key: 'related',
      doc: 'References to related rules (derived, obsoletes, merged, etc.)',
      required: false,
      example: 'related:\\n  - id: <uuid>\\n    type: derived',
    },
    {
      key: 'status',
      doc: 'Rule maturity status',
      required: false,
      example: 'status: experimental',
    },
    {
      key: 'description',
      doc: 'Detailed rule description (max 65535 characters)',
      required: false,
      example: 'description: Detects suspicious PowerShell activity...',
    },
    {
      key: 'references',
      doc: 'List of URLs with additional context',
      required: false,
      example: 'references:\\n  - https://example.com/threat-report',
    },
    {
      key: 'author',
      doc: 'Creator of the rule',
      required: false,
      example: 'author: John Doe',
    },
    {
      key: 'date',
      doc: 'Creation date (YYYY-MM-DD or YYYY/MM/DD)',
      required: false,
      example: 'date: 2024/01/15',
    },
    {
      key: 'modified',
      doc: 'Last modification date',
      required: false,
      example: 'modified: 2024/02/01',
    },
    {
      key: 'tags',
      doc: 'MITRE ATT&CK tags and custom tags',
      required: false,
      example: 'tags:\\n  - attack.execution\\n  - attack.t1059.001',
    },
    {
      key: 'logsource',
      doc: 'Log source definition (category, product, service)',
      required: true,
      example: 'logsource:\\n  category: process_creation\\n  product: windows',
    },
    {
      key: 'detection',
      doc: 'Detection logic with selections and condition',
      required: true,
      example: 'detection:\\n  selection:\\n    CommandLine|contains: suspicious\\n  condition: selection',
    },
    {
      key: 'fields',
      doc: 'Fields to include in output',
      required: false,
      example: 'fields:\\n  - CommandLine\\n  - User',
    },
    {
      key: 'falsepositives',
      doc: 'Known false positive scenarios',
      required: false,
      example: 'falsepositives:\\n  - Legitimate admin activity',
    },
    {
      key: 'level',
      doc: 'Alert severity level',
      required: false,
      example: 'level: high',
    },
  ] as SchemaItem[],

  status: [
    { value: 'stable', doc: 'Production-ready rule with minimal false positives' },
    { value: 'test', doc: 'Rule under testing, may need tuning' },
    { value: 'experimental', doc: 'New rule, may have false positives' },
    { value: 'deprecated', doc: 'Rule is deprecated, use replacement rule' },
    { value: 'unsupported', doc: 'Rule is no longer maintained' },
  ] as SchemaItem[],

  level: [
    { value: 'informational', doc: 'For tracking purposes, not direct alerting' },
    { value: 'low', doc: 'Low severity, minor impact if true positive' },
    { value: 'medium', doc: 'Medium severity, warrants investigation' },
    { value: 'high', doc: 'High severity, likely malicious activity' },
    { value: 'critical', doc: 'Critical severity, immediate response required' },
  ] as SchemaItem[],

  logsource: {
    keys: [
      { key: 'category', doc: 'Generic log source category (e.g., process_creation)' },
      { key: 'product', doc: 'Product or platform (e.g., windows, linux)' },
      { key: 'service', doc: 'Specific service within product (e.g., sysmon, security)' },
      { key: 'definition', doc: 'Optional human-readable description' },
    ] as SchemaItem[],

    category: [
      { value: 'process_creation', doc: 'Process start events (Sysmon EID 1, Windows EID 4688)' },
      { value: 'process_access', doc: 'Process memory access events (Sysmon EID 10)' },
      { value: 'process_termination', doc: 'Process end events (Sysmon EID 5)' },
      { value: 'image_load', doc: 'DLL/module load events (Sysmon EID 7)' },
      { value: 'file_event', doc: 'File creation events (Sysmon EID 11)' },
      { value: 'file_change', doc: 'File modification events' },
      { value: 'file_delete', doc: 'File deletion events (Sysmon EID 23)' },
      { value: 'file_rename', doc: 'File rename events' },
      { value: 'file_access', doc: 'File access events' },
      { value: 'registry_event', doc: 'Registry modification events (Sysmon EID 12-14)' },
      { value: 'registry_add', doc: 'Registry key/value creation events' },
      { value: 'registry_delete', doc: 'Registry key/value deletion events' },
      { value: 'registry_set', doc: 'Registry value set events' },
      { value: 'registry_rename', doc: 'Registry key/value rename events' },
      { value: 'network_connection', doc: 'Network connection events (Sysmon EID 3)' },
      { value: 'dns_query', doc: 'DNS query events (Sysmon EID 22)' },
      { value: 'dns', doc: 'DNS server/resolver events' },
      { value: 'firewall', doc: 'Firewall log events' },
      { value: 'proxy', doc: 'Web proxy log events' },
      { value: 'webserver', doc: 'Web server access logs' },
      { value: 'create_remote_thread', doc: 'Remote thread creation (Sysmon EID 8)' },
      { value: 'create_stream_hash', doc: 'Alternate data stream creation (Sysmon EID 15)' },
      { value: 'pipe_created', doc: 'Named pipe creation (Sysmon EID 17)' },
      { value: 'wmi_event', doc: 'WMI events (Sysmon EID 19-21)' },
      { value: 'driver_load', doc: 'Driver load events (Sysmon EID 6)' },
      { value: 'ps_module', doc: 'PowerShell module logging' },
      { value: 'ps_script', doc: 'PowerShell script block logging' },
      { value: 'ps_classic_start', doc: 'PowerShell classic start events' },
      { value: 'ps_classic_provider_start', doc: 'PowerShell classic provider start' },
      { value: 'ps_classic_script', doc: 'PowerShell classic script execution' },
      { value: 'sysmon_status', doc: 'Sysmon service status events' },
      { value: 'sysmon_error', doc: 'Sysmon error events' },
      { value: 'raw_access_thread', doc: 'Raw access read events (Sysmon EID 9)' },
      { value: 'clipboard_capture', doc: 'Clipboard capture events (Sysmon EID 24)' },
      { value: 'authentication', doc: 'Authentication/logon events' },
      { value: 'antivirus', doc: 'Antivirus detection events' },
    ] as SchemaItem[],

    product: [
      { value: 'windows', doc: 'Microsoft Windows' },
      { value: 'linux', doc: 'Linux systems' },
      { value: 'macos', doc: 'Apple macOS' },
      { value: 'aws', doc: 'Amazon Web Services' },
      { value: 'azure', doc: 'Microsoft Azure' },
      { value: 'gcp', doc: 'Google Cloud Platform' },
      { value: 'm365', doc: 'Microsoft 365' },
      { value: 'okta', doc: 'Okta identity platform' },
      { value: 'github', doc: 'GitHub' },
      { value: 'zeek', doc: 'Zeek network security monitor' },
      { value: 'cisco', doc: 'Cisco devices' },
      { value: 'fortinet', doc: 'Fortinet products' },
      { value: 'paloalto', doc: 'Palo Alto Networks' },
      { value: 'symantec', doc: 'Symantec/Broadcom products' },
      { value: 'crowdstrike', doc: 'CrowdStrike Falcon' },
      { value: 'sentinel_one', doc: 'SentinelOne' },
      { value: 'carbon_black', doc: 'VMware Carbon Black' },
      { value: 'qualys', doc: 'Qualys' },
      { value: 'netflow', doc: 'NetFlow/IPFIX data' },
      { value: 'juniper', doc: 'Juniper devices' },
      { value: 'bitdefender', doc: 'Bitdefender' },
      { value: 'kubernetes', doc: 'Kubernetes' },
      { value: 'docker', doc: 'Docker' },
      { value: 'spring', doc: 'Spring Framework' },
      { value: 'apache', doc: 'Apache products' },
      { value: 'nginx', doc: 'Nginx web server' },
      { value: 'sql', doc: 'SQL databases' },
      { value: 'modsecurity', doc: 'ModSecurity WAF' },
    ] as SchemaItem[],

    service: [
      { value: 'sysmon', doc: 'Sysmon (System Monitor)' },
      { value: 'security', doc: 'Windows Security event log' },
      { value: 'system', doc: 'Windows System event log' },
      { value: 'application', doc: 'Windows Application event log' },
      { value: 'powershell', doc: 'PowerShell event logs' },
      { value: 'powershell-classic', doc: 'PowerShell classic event logs' },
      { value: 'taskscheduler', doc: 'Task Scheduler event log' },
      { value: 'wmi', doc: 'WMI event log' },
      { value: 'windefend', doc: 'Windows Defender event log' },
      { value: 'dns-server', doc: 'Windows DNS Server' },
      { value: 'dhcp', doc: 'DHCP server logs' },
      { value: 'firewall-as', doc: 'Windows Firewall with Advanced Security' },
      { value: 'applocker', doc: 'AppLocker event log' },
      { value: 'bits-client', doc: 'BITS client events' },
      { value: 'codeintegrity-operational', doc: 'Code Integrity logs' },
      { value: 'ldap_debug', doc: 'LDAP debug logging' },
      { value: 'ntlm', doc: 'NTLM authentication' },
      { value: 'printservice-admin', doc: 'Print Service Admin' },
      { value: 'printservice-operational', doc: 'Print Service Operational' },
      { value: 'shell-core', doc: 'Shell Core events' },
      { value: 'terminalservices-localsessionmanager', doc: 'RDP Local Session Manager' },
      { value: 'capi2', doc: 'CAPI2 (Crypto API)' },
      { value: 'certificateservicesclient-lifecycle-system', doc: 'Certificate Services Client' },
      { value: 'vhdmp', doc: 'VHDMP Operational' },
      { value: 'auditd', doc: 'Linux auditd' },
      { value: 'auth', doc: 'Linux auth.log' },
      { value: 'sshd', doc: 'SSH daemon logs' },
      { value: 'sudo', doc: 'Sudo logs' },
      { value: 'cloudtrail', doc: 'AWS CloudTrail' },
      { value: 'cloudwatch', doc: 'AWS CloudWatch' },
      { value: 's3', doc: 'AWS S3 access logs' },
      { value: 'guardduty', doc: 'AWS GuardDuty' },
      { value: 'activitylogs', doc: 'Azure Activity Logs' },
      { value: 'signinlogs', doc: 'Azure Sign-in Logs' },
      { value: 'auditlogs', doc: 'Azure Audit Logs' },
    ] as SchemaItem[],
  },

  detection: {
    keys: [
      { key: 'selection', doc: 'Primary detection selection (any name allowed)' },
      { key: 'filter', doc: 'Filter to exclude false positives' },
      { key: 'condition', doc: 'Boolean expression combining selections' },
    ] as SchemaItem[],
  },

  modifiers: {
    generic: [
      { name: 'all', doc: 'Change OR to AND for list values. All values must match.' },
      { name: 'contains', doc: 'Match value anywhere in field. Adds wildcards around value.' },
      { name: 'startswith', doc: 'Match value at start of field. Adds wildcard at end.' },
      { name: 'endswith', doc: 'Match value at end of field. Adds wildcard at start.' },
      { name: 'exists', doc: 'Check if field exists. Value must be true or false.' },
      { name: 'cased', doc: 'Enable case-sensitive matching. Default is case-insensitive.' },
    ] as SchemaItem[],

    string: [
      { name: 'windash', doc: 'Match all dash variants (-, /, \\u2013, \\u2014, \\u2015)' },
      { name: 're', doc: 'Treat value as regular expression' },
      { name: 'base64', doc: 'Base64 encode the value before matching' },
      { name: 'base64offset', doc: 'Handle Base64 encoding at any offset position' },
      { name: 'wide', doc: 'UTF-16 little-endian encoding (alias for utf16le)' },
      { name: 'utf16le', doc: 'UTF-16 little-endian encoding' },
      { name: 'utf16be', doc: 'UTF-16 big-endian encoding' },
      { name: 'utf16', doc: 'UTF-16 encoding (both endian)' },
    ] as SchemaItem[],

    numeric: [
      { name: 'lt', doc: 'Less than comparison' },
      { name: 'lte', doc: 'Less than or equal comparison' },
      { name: 'gt', doc: 'Greater than comparison' },
      { name: 'gte', doc: 'Greater than or equal comparison' },
    ] as SchemaItem[],

    ip: [
      { name: 'cidr', doc: 'Match CIDR network range (IPv4 or IPv6)' },
    ] as SchemaItem[],
  },

  conditionKeywords: [
    { keyword: 'and', doc: 'Logical AND - both conditions must match' },
    { keyword: 'or', doc: 'Logical OR - either condition can match' },
    { keyword: 'not', doc: 'Logical NOT - negate the following condition' },
    { keyword: '1 of', doc: 'Match any one of the specified selections (e.g., 1 of selection*)' },
    { keyword: 'all of', doc: 'Match all of the specified selections (e.g., all of selection*)' },
    { keyword: 'them', doc: 'Reference all non-underscore-prefixed selections' },
  ] as SchemaItem[],

  taxonomyFields: {
    process_creation: [
      { field: 'CommandLine', doc: 'Command line used to start the process' },
      { field: 'Image', doc: 'Full path to the executable' },
      { field: 'OriginalFileName', doc: 'Original file name from PE header' },
      { field: 'ParentImage', doc: 'Full path to parent process executable' },
      { field: 'ParentCommandLine', doc: 'Command line of parent process' },
      { field: 'ParentUser', doc: 'User account of parent process' },
      { field: 'User', doc: 'User account running the process' },
      { field: 'LogonId', doc: 'Logon session ID' },
      { field: 'IntegrityLevel', doc: 'Process integrity level (Low, Medium, High, System)' },
      { field: 'CurrentDirectory', doc: 'Working directory of the process' },
      { field: 'ProcessId', doc: 'Process ID (PID)' },
      { field: 'ParentProcessId', doc: 'Parent process ID' },
      { field: 'Hashes', doc: 'File hashes (multiple algorithms)' },
      { field: 'md5', doc: 'MD5 hash of the executable' },
      { field: 'sha1', doc: 'SHA1 hash of the executable' },
      { field: 'sha256', doc: 'SHA256 hash of the executable' },
      { field: 'imphash', doc: 'Import hash of the executable' },
      { field: 'Company', doc: 'Company name from PE header' },
      { field: 'Description', doc: 'Description from PE header' },
      { field: 'Product', doc: 'Product name from PE header' },
      { field: 'FileVersion', doc: 'File version from PE header' },
    ] as SchemaItem[],

    network_connection: [
      { field: 'SourceIp', doc: 'Source IP address' },
      { field: 'SourcePort', doc: 'Source port number' },
      { field: 'DestinationIp', doc: 'Destination IP address' },
      { field: 'DestinationPort', doc: 'Destination port number' },
      { field: 'DestinationHostname', doc: 'Destination hostname' },
      { field: 'Protocol', doc: 'Network protocol (tcp, udp, etc.)' },
      { field: 'Image', doc: 'Process image initiating connection' },
      { field: 'User', doc: 'User account initiating connection' },
      { field: 'Initiated', doc: 'Whether connection was initiated (true) or received (false)' },
      { field: 'SourceHostname', doc: 'Source hostname' },
      { field: 'SourceIsIpv6', doc: 'Whether source is IPv6' },
      { field: 'DestinationIsIpv6', doc: 'Whether destination is IPv6' },
    ] as SchemaItem[],

    dns_query: [
      { field: 'QueryName', doc: 'DNS query name (domain)' },
      { field: 'QueryType', doc: 'DNS query type (A, AAAA, MX, etc.)' },
      { field: 'QueryResults', doc: 'DNS query results/answers' },
      { field: 'QueryStatus', doc: 'DNS query status code' },
      { field: 'Image', doc: 'Process image making DNS query' },
      { field: 'ProcessId', doc: 'Process ID making DNS query' },
    ] as SchemaItem[],

    dns: [
      { field: 'query', doc: 'DNS query name' },
      { field: 'answer', doc: 'DNS answer/response' },
      { field: 'record_type', doc: 'DNS record type (A, AAAA, CNAME, etc.)' },
      { field: 'parent_domain', doc: 'Parent domain of query' },
    ] as SchemaItem[],

    file_event: [
      { field: 'TargetFilename', doc: 'Full path to the target file' },
      { field: 'Image', doc: 'Process image creating the file' },
      { field: 'User', doc: 'User account creating the file' },
      { field: 'CreationUtcTime', doc: 'File creation time (UTC)' },
      { field: 'ProcessId', doc: 'Process ID creating the file' },
    ] as SchemaItem[],

    registry_event: [
      { field: 'TargetObject', doc: 'Full registry key path' },
      { field: 'Details', doc: 'Registry value data' },
      { field: 'EventType', doc: 'Registry event type (SetValue, DeleteValue, etc.)' },
      { field: 'Image', doc: 'Process image modifying registry' },
      { field: 'User', doc: 'User account modifying registry' },
      { field: 'ProcessId', doc: 'Process ID modifying registry' },
    ] as SchemaItem[],

    image_load: [
      { field: 'ImageLoaded', doc: 'Full path to loaded DLL/module' },
      { field: 'Image', doc: 'Process image loading the module' },
      { field: 'Signed', doc: 'Whether the module is signed' },
      { field: 'SignatureStatus', doc: 'Signature validation status' },
      { field: 'Signature', doc: 'Signature signer' },
      { field: 'Hashes', doc: 'File hashes of loaded module' },
      { field: 'Company', doc: 'Company name from PE header' },
      { field: 'Description', doc: 'Description from PE header' },
      { field: 'Product', doc: 'Product name from PE header' },
      { field: 'OriginalFileName', doc: 'Original file name from PE header' },
    ] as SchemaItem[],

    firewall: [
      { field: 'src_ip', doc: 'Source IP address' },
      { field: 'src_port', doc: 'Source port' },
      { field: 'dst_ip', doc: 'Destination IP address' },
      { field: 'dst_port', doc: 'Destination port' },
      { field: 'action', doc: 'Firewall action (allow, deny, drop)' },
      { field: 'protocol', doc: 'Network protocol' },
      { field: 'username', doc: 'Associated username' },
    ] as SchemaItem[],

    proxy: [
      { field: 'c-uri', doc: 'Client request URI' },
      { field: 'c-uri-query', doc: 'Client request URI query string' },
      { field: 'c-uri-stem', doc: 'Client request URI path' },
      { field: 'c-useragent', doc: 'Client user agent string' },
      { field: 'cs-host', doc: 'Request host header' },
      { field: 'cs-method', doc: 'HTTP method (GET, POST, etc.)' },
      { field: 'cs-cookie', doc: 'Request cookies' },
      { field: 'cs-referrer', doc: 'Request referrer header' },
      { field: 'sc-status', doc: 'HTTP response status code' },
      { field: 'cs-bytes', doc: 'Client bytes sent' },
      { field: 'sc-bytes', doc: 'Server bytes received' },
      { field: 'r-dns', doc: 'Resolved DNS name' },
      { field: 'c-ip', doc: 'Client IP address' },
      { field: 's-ip', doc: 'Server IP address' },
    ] as SchemaItem[],

    webserver: [
      { field: 'cs-uri', doc: 'Client request URI' },
      { field: 'cs-uri-query', doc: 'Client request URI query' },
      { field: 'cs-uri-stem', doc: 'Client request URI path' },
      { field: 'cs-method', doc: 'HTTP method' },
      { field: 'c-useragent', doc: 'Client user agent' },
      { field: 'c-ip', doc: 'Client IP address' },
      { field: 'cs-host', doc: 'Request host header' },
      { field: 'sc-status', doc: 'HTTP response status' },
      { field: 'cs-referrer', doc: 'Request referrer' },
    ] as SchemaItem[],

    authentication: [
      { field: 'TargetUserName', doc: 'Target username for authentication' },
      { field: 'TargetDomainName', doc: 'Target domain name' },
      { field: 'LogonType', doc: 'Type of logon (interactive, network, etc.)' },
      { field: 'Status', doc: 'Authentication status code' },
      { field: 'SubStatus', doc: 'Authentication substatus code' },
      { field: 'WorkstationName', doc: 'Source workstation name' },
      { field: 'IpAddress', doc: 'Source IP address' },
      { field: 'IpPort', doc: 'Source port' },
      { field: 'AuthenticationPackageName', doc: 'Authentication package (NTLM, Kerberos)' },
      { field: 'LogonProcessName', doc: 'Logon process name' },
    ] as SchemaItem[],

    driver_load: [
      { field: 'ImageLoaded', doc: 'Full path to driver file' },
      { field: 'Signed', doc: 'Whether driver is signed' },
      { field: 'SignatureStatus', doc: 'Signature validation status' },
      { field: 'Signature', doc: 'Signature signer' },
      { field: 'Hashes', doc: 'File hashes of driver' },
    ] as SchemaItem[],

    create_remote_thread: [
      { field: 'SourceImage', doc: 'Process creating the remote thread' },
      { field: 'SourceProcessId', doc: 'PID of source process' },
      { field: 'TargetImage', doc: 'Target process receiving thread' },
      { field: 'TargetProcessId', doc: 'PID of target process' },
      { field: 'NewThreadId', doc: 'ID of the new thread' },
      { field: 'StartAddress', doc: 'Start address of new thread' },
      { field: 'StartFunction', doc: 'Start function name' },
      { field: 'StartModule', doc: 'Module containing start address' },
    ] as SchemaItem[],

    process_access: [
      { field: 'SourceImage', doc: 'Process accessing another process' },
      { field: 'SourceProcessId', doc: 'PID of source process' },
      { field: 'TargetImage', doc: 'Target process being accessed' },
      { field: 'TargetProcessId', doc: 'PID of target process' },
      { field: 'GrantedAccess', doc: 'Access rights granted' },
      { field: 'CallTrace', doc: 'Call stack trace' },
    ] as SchemaItem[],

    pipe_created: [
      { field: 'PipeName', doc: 'Name of the created pipe' },
      { field: 'Image', doc: 'Process image creating the pipe' },
      { field: 'User', doc: 'User account creating the pipe' },
      { field: 'ProcessId', doc: 'Process ID creating the pipe' },
    ] as SchemaItem[],

    wmi_event: [
      { field: 'EventType', doc: 'WMI event type (subscription, consumer, binding)' },
      { field: 'Operation', doc: 'WMI operation performed' },
      { field: 'User', doc: 'User account' },
      { field: 'Name', doc: 'Event name' },
      { field: 'Query', doc: 'WMI query' },
      { field: 'Consumer', doc: 'Event consumer' },
      { field: 'Destination', doc: 'Event destination' },
    ] as SchemaItem[],

    ps_module: [
      { field: 'ContextInfo', doc: 'PowerShell context information' },
      { field: 'Payload', doc: 'PowerShell module payload' },
    ] as SchemaItem[],

    ps_script: [
      { field: 'ScriptBlockText', doc: 'PowerShell script block content' },
      { field: 'ScriptBlockId', doc: 'Script block identifier' },
      { field: 'Path', doc: 'Script file path (if applicable)' },
    ] as SchemaItem[],
  } as Record<string, SchemaItem[]>,

  relatedTypes: [
    { value: 'derived', doc: 'Rule is derived from another rule' },
    { value: 'obsoletes', doc: 'Rule obsoletes/replaces another rule' },
    { value: 'merged', doc: 'Rule is a merge of other rules' },
    { value: 'renamed', doc: 'Rule was renamed from another rule' },
    { value: 'similar', doc: 'Rule is similar to another rule' },
  ] as SchemaItem[],
}

/**
 * Get all modifiers as a flat array
 */
export function getAllModifiers(): SchemaItem[] {
  return [
    ...SIGMA_SCHEMA.modifiers.generic,
    ...SIGMA_SCHEMA.modifiers.string,
    ...SIGMA_SCHEMA.modifiers.numeric,
    ...SIGMA_SCHEMA.modifiers.ip,
  ]
}

/**
 * Get taxonomy fields for a specific category
 */
export function getTaxonomyFields(category: string): SchemaItem[] {
  return SIGMA_SCHEMA.taxonomyFields[category] || []
}

/**
 * Get all taxonomy field names (for generic detection context)
 */
export function getAllTaxonomyFields(): SchemaItem[] {
  const allFields: SchemaItem[] = []
  const seen = new Set<string>()

  for (const fields of Object.values(SIGMA_SCHEMA.taxonomyFields)) {
    for (const field of fields) {
      if (!seen.has(field.field!)) {
        seen.add(field.field!)
        allFields.push(field)
      }
    }
  }

  return allFields
}

/**
 * Find documentation for a keyword/value
 */
export function findDocumentation(word: string): SchemaItem | null {
  // Check top-level keys
  const topLevel = SIGMA_SCHEMA.topLevelKeys.find((k) => k.key === word)
  if (topLevel) return topLevel

  // Check status values
  const status = SIGMA_SCHEMA.status.find((s) => s.value === word)
  if (status) return status

  // Check level values
  const level = SIGMA_SCHEMA.level.find((l) => l.value === word)
  if (level) return level

  // Check logsource keys
  const logsourceKey = SIGMA_SCHEMA.logsource.keys.find((k) => k.key === word)
  if (logsourceKey) return logsourceKey

  // Check logsource categories
  const category = SIGMA_SCHEMA.logsource.category.find((c) => c.value === word)
  if (category) return category

  // Check logsource products
  const product = SIGMA_SCHEMA.logsource.product.find((p) => p.value === word)
  if (product) return product

  // Check logsource services
  const service = SIGMA_SCHEMA.logsource.service.find((s) => s.value === word)
  if (service) return service

  // Check detection keys (condition, selection, filter)
  const detectionKey = SIGMA_SCHEMA.detection.keys.find((k) => k.key === word)
  if (detectionKey) return detectionKey

  // Check modifiers
  const modifier = getAllModifiers().find((m) => m.name === word)
  if (modifier) return modifier

  // Check condition keywords
  const conditionKeyword = SIGMA_SCHEMA.conditionKeywords.find((k) => k.keyword === word)
  if (conditionKeyword) return conditionKeyword

  // Check taxonomy fields
  const taxonomyField = getAllTaxonomyFields().find((f) => f.field === word)
  if (taxonomyField) return taxonomyField

  return null
}
