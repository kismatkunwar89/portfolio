# Flamingo Neck Networks Internal Pentest (Course Lab)

Course lab report documenting an internal penetration test of a simulated corporate network (10.248.1.0/24, ICS hosts excluded).

Highlights:
- Chained default PostgreSQL credentials into remote code execution on storage host.
- Leveraged guest-as-admin misconfiguration to perform Pass-the-Hash and fully compromise Active Directory (NTDS.dit/krbtgt).
- Documented 9 findings (2 Critical, 1 High) with remediation and network topology.

Artifacts:
- `lab5final.pdf` — full report.
