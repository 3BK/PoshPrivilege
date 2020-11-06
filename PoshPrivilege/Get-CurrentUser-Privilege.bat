@set MY_CWD=%cd%
PowerShell -NoProfile -ExecutionPolicy Bypass -Command " Import-Module '%MY_CWD%\PoshPrivilege.psm1'; Get-Privilege -CurrentUser"
