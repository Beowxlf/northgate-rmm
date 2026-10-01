// NorthGate starter rules. Licensed under Apache-2.0 (repository LICENSE).
// Matches are triage observations, not malware verdicts. No file is executed.

rule NorthGate_Qualification_Marker {
    meta:
        description = "Harmless marker used to verify the scanner and case evidence path"
        classification = "qualification"
        severity = "informational"
    strings:
        $marker = "NORTHGATE_RMM_YARA_QUALIFICATION_v1" ascii
    condition:
        filesize < 1048576 and $marker
}

rule NorthGate_Download_And_Expression_Execution {
    meta:
        description = "Script includes both a web download and dynamic expression execution"
        classification = "triage_requires_review"
        severity = "medium"
        false_positives = "Approved installation and administration scripts"
    strings:
        $download1 = "Invoke-WebRequest" ascii wide nocase
        $download2 = "DownloadString(" ascii wide nocase
        $download3 = "Invoke-RestMethod" ascii wide nocase
        $execute1 = "Invoke-Expression" ascii wide nocase
        $execute2 = /\biex[ \t]*\(/ ascii wide nocase
    condition:
        filesize < 1048576 and 1 of ($download*) and 1 of ($execute*)
}

rule NorthGate_Encoded_PowerShell_Invocation {
    meta:
        description = "PowerShell invocation includes a substantial encoded command argument"
        classification = "triage_requires_review"
        severity = "medium"
        false_positives = "Approved automation and software deployment wrappers"
    strings:
        $shell = /(powershell|pwsh)(\.exe)?/ ascii wide nocase
        $encoded = /-enc(odedcommand)?[ \t]+[A-Za-z0-9+\/=]{40,512}/ ascii wide nocase
    condition:
        filesize < 1048576 and $shell and $encoded
}

rule NorthGate_Download_Piped_To_Shell {
    meta:
        description = "Text contains a downloader pipeline into a command shell"
        classification = "triage_requires_review"
        severity = "medium"
        false_positives = "Approved bootstrap documentation and installer commands"
    strings:
        $pipeline = /(curl|wget)[^\r\n]{1,200}\|[ \t]*(sh|bash)\b/ ascii
    condition:
        filesize < 1048576 and $pipeline
}
