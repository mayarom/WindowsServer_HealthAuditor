#Writen By Einav Pincu
#The script is aimed at Auditors, PenTesters and SysAdmins to evaluate the hardening of an Exchange 2016 server.
#This script will run through several checks and for each check output to the terminal 'OK' or the miss configuration found
#The checks are designed to test whether or not the exchange server conforms to the benchmarks in the
#The document "CIS_Microsoft_Exchange_Server_2016_Benchmark_v1.0.0" found on
#https://benchmarks.cisecurity.org
#created on 08/09/2019.

clear
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;
#sent message size
$a = Get-SendConnector MaxMessageSize
if ([int]$a.MaxMessageSize -gt 10240){
write-host "send message size is'nt limited to 10240KB`nyou need to run this command: Set-SendConnector -MaxMessageSize 10240KB"
}
else {write-host "send message size is ok" }
#income message size
$a = Get-TransportConfig
$b= $a.MaxReceiveSize.Value
if ($b -ne "10 MB"){
write-host "incoming message size is'nt limited to 10240KB`nyou need to run this command: Set-TransportConfig -MaxReceiveSize 10240KB"
}
else {write-host "incoming message size is ok" }
#use DNS to route outbound mail
$a =Get-SendConnector  
if ([string]$a.DNSRoutingEnabled -ne "True"){
write-host "you need to use DNS to route outbound mail`nyou need to run this command: Set-SendConnector -DNSRoutingEnabled $true"
}
else {write-host "use DNS to route outbound mail is ok" }

#Sender ID agent
$a =Get-SenderIdConfig
write-host $a.Enabled
if ($a.Enabled -ne "True"){
write-host "Sender ID agent is disable`nyou need to run this command:Set-SenderIDConfig -Enabled $true"
}
else {write-host "Sender ID agent is ok" }
#sender filtering
$a = Get-SenderFilterConfig 
if ($a.Enabled -ne "true"){
write-host "sender filtering is disable`nyou need to run this command:Set-SenderFilterConfig -Enabled $true"
}
else {write-host "sender filtering is ok" }
#Secure Pop3
$a =Get-PopSettings
if ($a.LoginType -ne "SecureLogin"){
write-host "pop3 not secure`nyou need to run this command:Set-PopSettings -LoginType SecureLogin"
}
else {write-host "Secure Pop3 is ok" }
#message tracking log 
$a = Get-TransportService 
if ($a.MessageTrackingLogEnabled -ne "true"){
write-host "message tracking log is disable`nyou need to run this command:Set-TransportService -MessageTrackingLogEnabled $true"
}
else {write-host "message tracking log is ok" }
#secure IMAP4
$a = Get-ImapSettings 
if ($a.LoginType -ne "SecureLogin"){
write-host "secure IMAP4 is disable`nyou need to run this command: Set-ImapSettings -LoginType SecureLogin"
}
else {write-host "secure IMAP4 is ok" }
#Connectivity logs
$a = Get-TransportService  
if ($a.ConnectivityLogEnabled -ne "true"){
write-host "Connectivity logs is not mointored`nyou need to run this command: Set-TransportService -ConnectivityLogEnabled $true"
}
else {write-host "Connectivity logs is ok" }
#Maximum send size - organization level
$a = Get-TransportConfig  
if ($a.MaxSendSize.Value -ne "10 MB"){
write-host "Maximum send size - organization level is greater then 10240KB `nyou need to run this command: Set-TransportConfig -MaxSendSize 10240KB"
}
else {write-host "Maximum send size - organization level is ok" }
#Maximum receive size - connector level
$a = Get-ReceiveConnector 
if ($a.MaxMessageSize -ne "10 MB"){
write-host "Maximum receive size - connector level is greater then 10240KB `nyou need to run this command: Set-TransportConfig -MaxSendSize 10240KB"
}
else {write-host "Maximum receive size - connector level is ok" }
#Mailbox quotas warning
$a = Get-MailboxDatabase 
if ($a.IssueWarningQuota.Value -ne "1.899 GB (2,039,480,320 bytes)"){
write-host "Mailbox quotas warning is disable `nyou need to run this command:Set-MailboxDatabase -IssueWarningQuota 1991680KB"
}
else {write-host "Mailbox quotas warning is ok" }
#Mailbox quotas: Prohibit send and receive at 2411520
$a = Get-MailboxDatabase 
if ($a.ProhibitSendReceiveQuota.Value -ne "2.3 GB (2,469,396,480 bytes)"){
write-host "Mailbox quotas prohibit send and receive at limit is disable `nyou need to run this command:Set-MailboxDatabase -ProhibitSendReceiveQuota 2411520KB"
}
else {write-host "Mailbox quotas: Prohibit send and receive at 2411520 is ok" }
#Mailbox quotas: Prohibit send at 2097152
$a = Get-MailboxDatabase   
if ($a.ProhibitSendQuota.Value -ne "2 GB (2,147,483,648 bytes)"){
write-host "Mailbox quotas prohibit send messegas when their mailbox is approaching its size limit is disable `nyou need to run this command: Set-MailboxDatabase  -ProhibitSendQuota 2097152KB"
}
else {write-host "Mailbox quotas: Prohibit send at 2097152 is ok" }

#Communications between Outlook and Exchange encryption
$a = Get-RpcClientAccess 
if ($a.EncryptionRequired -ne "true"){
write-host "Communications between Outlook and Exchange is not encrypted `nyou need to run this command:Set-RpcClientAccess -EncryptionRequired $true "
}
else {write-host "Communications between Outlook and Exchange encryption is ok" }
#Administrator Audit Logging 
$a = Get-AdminAuditLogConfig  
if ($a.AdminAuditLogCmdlets -ne "*"){
write-host "Administrator Audit Logging is off`nyou need to run this command:Set-AdminAuditLogConfig -AdminAuditLogCmdlets * "
}
else {write-host "Administrator Audit Logging is ok" }
#script execution limitation
$a = Get-ExecutionPolicy 
if ([string]$a -ne "RemoteSigned"){
write-host "script execution limitation is not activated`nyou need to run this command:Set-ExecutionPolicy RemoteSigned "
}
else {write-host "script execution limitation is ok" }
#Administrator Audit Logging 
$a =Get-AdminAuditLogConfig
if ($a.AdminAuditLogEnabled -ne "True"){
write-host "Administrator Audit Logging is off`nyou need to run this command:Set-AdminAuditLogConfig -AdminAuditLogEnabled $True"
}
else {write-host "Administrator Audit Logging is ok" }
#automatic replies to remote domains
$a = Get-RemoteDomain -Identity Default  
if ([string]$a.AutoReplyEnabled -ne "False"){
write-host "automatic replies to remote domains is activated`nyou need to run this command:Set-RemoteDomain -Identity Default -AutoReplyEnabled $false "
}
else {write-host "automatic replies to remote domains is ok" }
#basic authentication disallow
$a = Get-OwaVirtualDirectory
if ([string]$a.BasicAuthentication -ne "False"){
write-host "basic authentication is allowed `nyou need to run this command:Set-OwaVirtualDirectory -Identity `"owa (Default Web Site)`" -BasicAuthentication $false "
}
else {write-host "basic authentication disallow is ok" }
#non-delivery reports
$a = Get-RemoteDomain
if ($a.NDREnabled -ne "False"){
write-host "non-delivery reports is on`nyou need to run this command:Set-RemoteDomain -NDREnabled $false "
}
else {write-host "non-delivery reports is ok" }
#automatic forwards to remote domains
$a =Get-RemoteDomain
if ([string]$a.AutoForwardEnabled  -ne "False"){
write-host "automatic forwards to remote domains is on`nyou need to run this command:Set-RemoteDomain -AutoForwardEnabled $false "
}
else {write-host "automatic forwards to remote domains is ok" }
#Enable S/MIME for OWA 2010
$a = Get-OWAVirtualDirectory 
if ($a.SMimeEnabled -ne "True"){
write-host "S/MIME for OWA 2010 is off`nyou need to run this command: Set-OWAVirtualDirectory -identity `"owa (Default Web Site)`" -SMimeEnabled $true"
}
else {write-host "Enable S/MIME for OWA 2010 is ok" }
#Administrator Audit Logging
$a = Get-AdminAuditLogConfig 
if ($a.AdminAuditLogEnabled -ne "True"){
write-host "Administrator Audit Logging is off`nyou need to run this command: Set-AdminAuditLogConfig -AdminAuditLogEnabled $true"
}
else {write-host "Administrator Audit Logging is ok" }

#to Configure SSL for Exchange ActiveSync you need to follow the instruction in this link https://docs.microsoft.com/en-us/previous-versions/office/exchange-server-2010/bb266938(v=exchg.141)
#to perform this action- Set 'External send connector authentication: Ignore Start TLS' to 'False', you need a paremater called connector_name, then, replace <connector_name> with the actual name and run this commands:
#$a = Get-SendConnector -identity <connector_name>  
#if ([string]$a.IgnoreSTARTTLS -ne "false"){
#write-host "you need to run this command:set-SendConnector -identity <connector_name> -IgnoreSTARTTLS: $false "
#}
#to perform this action- Set receive connector 'Configure Protocol logging' to 'Verbose', you need a paremater called IDENTITY, then, replace <IDENTITY> with the actual name and run this commands:
#$a = Get-ReceiveConnector "<IDENTITY>"  
#if ([string]$a.ProtocolLoggingLevel -ne "Verbose"){
#write-host "you need to run this command:Set-ReceiveConnector "<IDENTITY>" -ProtocolLoggingLevel Verbose"
#}
#to perform this action- Set 'External send connector authentication: Domain Security' to 'True', you need a paremater called SendConnectorIdParameter, then, replace <SendConnectorIdParameter> with the actual name and run this commands:
#$a = get-sendconnector -Identity <SendConnectorIdParameter>  
#if ([string]$a.DomainSecureEnabled -ne "true"){
#write-host "you need to run this command:set-sendconnector -Identity <SendConnectorIdParameter> -DomainSecureEnabled $true"
#}
#to perform this action- limit the number of people who can recive a message, you need your exchange server name,then replace <Server01> with the actual name and run this commands:
#$a =Get-TransportService -Identity "Server01" 
#if ([int]$a.PickupDirectoryMaxRecipientsPerMessage -gt 5000){
#write-host "the number of people who can recive a message is greater then 5000`nyou need to run this command: Set-TransportService -Identity `"Server01`" -PickupDirectoryMaxRecipientsPerMessage 5000"
#}



##if you want to configure mobile devices restriction run the commends below:
#strong password
#$a = Get-MobileDeviceMailboxPolicy
#if ([string]$a.AllowSimplePassword -ne "False"){
#write-host "simple password is avilable `nyou need to run this command: Set-MobileDeviceMailboxPolicy <Profile> -AllowSimplePassword $false"
#}
#else {write-host "strong password is ok" }
#Password history limit - 4
#$a = Get-MobileDeviceMailboxPolicy 
#if ([int]$a.PasswordHistory -lt 4){
#write-host "the same password can be used multiple times`nyou need to run this command:Set-MobileDeviceMailboxPolicy <Profile> -PasswordHistory 4 "
#}
#else {write-host "Password history limit - 4 is ok" }
#Password Expiration
#$a = Get-MobileDeviceMailboxPolicy   
#if ([int]$a.PasswordExpiration -gt 90){
#write-host "the password need to be expired in 90 days or less`nyou need to run this command:Set-MobileDeviceMailboxPolicy default -PasswordExpiration 90 "
#}
#else {write-host "Password Expiration is ok" }
#Minimum password length - 8 
#$a = Get-MobileDeviceMailboxPolicy  
#if ([int]$a.MinPasswordLength -lt 8){
#write-host "the password length need to be greater then 7`nyou need to run this command: Set-MobileDeviceMailboxPolicy default -MinPasswordLength 4"
#}
#else {write-host "Minimum password length - 8 is ok" }
#refresh policy every hour
#$a = Get-MobileDeviceMailboxPolicy -Identity default
#if ([string]$a.DevicePolicyRefreshInterval -gt "1:00:00"){
#write-host "the policy setting should be refreshed every hour `nyou need to run this command:Set-MobileDeviceMailboxPolicy -Identity default -DevicePolicyRefreshInterval '1:00:00' "
#}
#else {write-host "refresh policy every hour is ok" }
#unmanaged devices will be disallowed
#$a = Get-MobileDeviceMailboxPolicy -Identity default  
#if ([string]$a.AllowNonProvisionableDevices -ne "False"){
#write-host "unmanaged devices are not disallowed `nyou need to run this command:Set-MobileDeviceMailboxPolicy -Identity default -AllowNonProvisionableDevices $false "
#}
#else {write-host "unmanaged devices will be disallowed is ok" }
#encryption on device
#$a = Get-MobileDeviceMailboxPolicy -Identity default  
#if ([string]$a.RequireDeviceEncryption -ne "true"){
#write-host "encryption on device is not activated `nyou need to run this command:Set-MobileDeviceMailboxPolicy -Identity default -RequireDeviceEncryption $true "
#}
#else {write-host "encryption on device is ok" }
#Require alphanumeric password
#$a = Get-MobileDeviceMailboxPolicy -Identity Default  
#if ([string]$a.AlphanumericPasswordRequired -ne "true"){
#write-host "Require alphanumeric password  is not activated`nyou need to run this command:Set-MobileDeviceMailboxPolicy -Identity Default -AlphanumericPasswordRequired $true "
#}
#else {write-host "Require alphanumeric password is ok" }

#failed logon attempts 
#$a = Get-MobileDeviceMailboxPolicy -Identity Default  
#if ([int]$a.MaxPasswordFailedAttempts -gt 5){
#write-host "failed logon attempts is unlimited `nyou need to run this command: Set-MobileDeviceMailboxPolicy -Identity Default -MaxPasswordFailedAttempts 5"
#}
#else {write-host "failed logon attempts is ok" }