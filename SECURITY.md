# Security policy

## Reporting a vulnerability

Please report security issues privately, through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository's **Security** tab. Do not open a public issue.

Expect a first reply within a week. This is a small project maintained in spare
time; there is no bounty.

## What is in scope

These tools run privileged commands on the machine, so the interesting failures
are all in that boundary:

- a command that executes without having been previewed and confirmed;
- a preview that does not match what is executed;
- an argument taken from a config file, a theme file or parsed command output
  that reaches a shell or changes the meaning of the command line;
- privilege escalation beyond the configured prefix.

## What is not

- Anything the user can already do with the underlying tool at the same
  privilege level. These are terminal front ends, not a privilege boundary of
  their own.
- Needing root to change the system. That is the design.
- Locking yourself out of a machine by writing a rule that does so. The tool
  previews and warns; it does not second-guess an administrator.

## Supported versions

The latest release only, until v1.
