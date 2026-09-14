# NorthGate starter YARA-X rules

These on-demand file rules identify a harmless qualification marker and three
script patterns worth analyst review: download plus expression execution,
encoded PowerShell invocation, and a downloader pipeline into a shell. They do
not execute matched content, upload files, quarantine anything, or establish a
malware verdict. Legitimate administrative scripts and documentation can match.

The initial rules are deliberately small. Expand them through reviewed signed
package revisions with representative positive and negative fixtures. Preserve
the upstream YARA-X BSD-3-Clause license and the repository Apache-2.0 license
for these rules. The RMM recipe uses one thread, a per-file size limit, execution
deadline, bounded output, and the worker's process-tree resource controls.

The qualification marker is `NORTHGATE_RMM_YARA_QUALIFICATION_v1`. It is ordinary
text and is not the EICAR antivirus test string.
