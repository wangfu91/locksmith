# Locksmith privacy policy

Last updated: October 10, 2026

Locksmith is a free, open-source Windows command-line utility maintained by
Fu Wang. It identifies processes using a file or directory on your computer.

## Information accessed locally

When you provide a path, Locksmith accesses that path and queries Windows for
open file handles and loaded modules. It displays matching process IDs,
executable names, and executable paths in your terminal. These paths may contain
your Windows username or other personal information in file and folder names.
Locksmith uses this information only to carry out the scan you request.

If you use the optional `--kill` command, Locksmith asks for confirmation before
requesting termination of matching processes. Termination is subject to Windows
access controls and can cause loss of unsaved work.

## Collection, storage, and sharing

Locksmith does not send network requests, collect analytics or telemetry, use
cookies or advertising, or require an account. It does not transmit your paths,
process details, or scan results to the developer or any other party. It does not
create persistent scan histories, reports, or log files itself.

Your terminal may retain output in its scrollback. If you redirect output to a
file or share it, you control that copy and its retention. Avoid sharing output
that contains private file names or personal information.

Windows and the Microsoft Store may separately process information when you
obtain, install, update, or run software. Their processing is governed by their
own privacy policies, including the
[Microsoft Privacy Statement](https://privacy.microsoft.com/privacystatement).

## Your choices

You choose the file or directory to scan. You may cancel process termination at
the confirmation prompt, stop the program, or uninstall it. No information is
stored on a developer-operated server for you to request or delete.

## Support and contact

For privacy questions, contact the maintainer through the
[Locksmith project](https://github.com/wangfu91/locksmith). GitHub issues are
public: do not include private paths, process output, or other personal data in
an issue. Information you choose to share on GitHub is subject to
[GitHub's privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

## Changes

This policy will be updated if Locksmith's data practices change. The date above
identifies the latest revision.
