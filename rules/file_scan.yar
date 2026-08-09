rule Suspicious_Encoded_PowerShell
{
    meta:
        description = "PowerShell command appears to use encoded input"
        severity = 70
    strings:
        $powershell = /powershell(\.exe)?/ nocase
        $encoded = / -(enc|encodedcommand)( |:)/ nocase
    condition:
        all of them
}

rule Suspicious_Download_And_Execute
{
    meta:
        description = "Script combines a download primitive with process execution"
        severity = 80
    strings:
        $download_1 = "DownloadString" nocase
        $download_2 = "Invoke-WebRequest" nocase
        $execute_1 = "Start-Process" nocase
        $execute_2 = "Invoke-Expression" nocase
    condition:
        1 of ($download_*) and 1 of ($execute_*)
}
