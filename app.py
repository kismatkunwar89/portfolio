from pathlib import Path
import streamlit as st

st.set_page_config(
    page_title="Kismat Kunwar - Portfolio",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# --- Assets ---
profile_path = Path("1744998645235.jpeg")
resume_path = Path("resume.pdf")
ccna_path = Path("ccna_600.png")
cc_path = Path("Certified in Cybersecurity (CC).png")
az_path = Path("microsoft-certified-fundamentals-badge.svg")
brutus_writeup_path = Path("writeups/Brutus.md")

# --- Content Data ---
about_text = (
    "Master's in Cybersecurity student at the University of New Haven with hands-on work in "
    "endpoint security, threat mitigation, vulnerability management, and digital forensics. "
    "Currently deepening networking and network security skills while exploring practical AI agent use."
)

skills_col_1 = [
    ("CrowdStrike / EDR", 85),
    ("Threat Hunting", 80),
    ("Windows Server / AD", 82),
    ("Azure / Cloud", 50),
    ("Artificial Intelligence", 30),
]

skills_col_2 = [
    ("Networking (CCNA)", 78),
    ("Digital Forensics", 75),
    ("Python / Scripting", 70),
    ("Linux / Kali", 72),
    ("Prompt Engineering", 80),
    ("Retrieval Augmented Generation", 50),
]

projects = [
    {
        "title": "Reliable, Scalable Network Design",
        "details": "Redundant three-tier network for 170 users with OSPF, VLANs, ACLs, VPN, and AAA. 80% emulated in Cisco Packet Tracer.",
        "link": "https://github.com/kismatkunwar89/NetworkProject",
    },
    {
        "title": "Malware Research and Development",
        "details": "APT evasion research with simulated C2 (Metasploit and Cobalt Strike) achieving high evasion on Windows testbeds.",
        "link": "https://github.com/kismatkunwar89/FinalYearProject-Malware-Development",
    },
    {
        "title": "Windows Server and Client Lab",
        "details": "Virtualized lab with Server 2022 and Windows 10. Configured AD DS, DNS, DHCP, GPO, IIS, WSUS, FSRM, and PowerShell automation.",
        "link": None,
    },
]

experience = [
    {
        "role": "Provost Research Assistant",
        "org": "University of New Haven",
        "time": "Sep 2024 - Present | West Haven, CT",
        "bullets": [
            "Researched anti-forensics and standardized artifacts with CASE/UCO to improve interoperability and investigation accuracy.",
            "Engineered prompts for LLMs to automate standardization, cutting manual definition time about 30% with strong semantic accuracy.",
        ],
    },
    {
        "role": "Security Support Intern",
        "org": "Raechal Enterprise Pvt Ltd",
        "time": "May 2023 - Mar 2024 | Kathmandu, Nepal",
        "bullets": [
            "Built threat-detection use cases and demos for CrowdStrike EDR, contributing to more client acquisitions and renewals.",
            "Configured Falcon EDR for banking clients; supported PCI DSS compliance and endpoint incident response.",
            "Resolved weekly EDR and MFA tickets while collaborating with SOC analysts.",
        ],
    },
]

education = [
    {
        "degree": "Master's in Cybersecurity",
        "school": "University of New Haven",
        "time": "Aug 2024 - Present",
        "notes": "GPA 3.9. Courses: Enterprise Network Design, Network Defense, Threat Hunting, Windows/Linux Administration, AI and Cybersecurity.",
    },
    {
        "degree": "Bachelor's in Cybersecurity",
        "school": "Coventry University",
        "time": "May 2020 - Jun 2023",
        "notes": "First Class Honors (GPA 3.96). Courses: Advanced Networking, Advanced Digital Forensics, Pen Testing, Python, System Security.",
    },
]

certifications = [
    {
        "title": "Cisco Certified Network Associate (CCNA)",
        "image": ccna_path,
        "link": "https://www.credly.com/badges/c0a58046-8207-4140-bdb3-df9d6bcf4d25/linked_in_profile",
    },
    {
        "title": "Microsoft Certified: Azure Fundamentals (AZ-900)",
        "image": az_path,
        "link": "https://learn.microsoft.com/en-us/users/kismatkunwar-6406/credentials/e499a39dc338e04f",
    },
    {
        "title": "ISC2 Certified in Cybersecurity (CC)",
        "image": cc_path,
        "link": "https://www.credly.com/badges/1dc588c2-1875-4dca-b3b2-0db04ac27849/linked_in_profile",
    },
]

achievements = [
    "Provost's Assistantship Award 2024-26 - University of New Haven.",
    "Outstanding Academic Excellence and Top of Cohort 2023 - Softwarica College.",
]

writeups = [
    {
        "title": "Brutus",
        "path": brutus_writeup_path,
        "summary": "SSH brute-force investigation using auth.log and wtmp.",
    },
]


def section_title(text: str) -> None:
    st.markdown(f"#### {text}")


def render_skills() -> None:
    section_title("Skills")
    col1, col2 = st.columns(2)
    for name, level in skills_col_1:
        with col1:
            st.write(name)
            st.progress(level)
    for name, level in skills_col_2:
        with col2:
            st.write(name)
            st.progress(level)


def render_projects() -> None:
    section_title("Projects")
    cols = st.columns(2)
    for idx, project in enumerate(projects):
        with cols[idx % 2]:
            st.markdown(f"**{project['title']}**")
            st.write(project["details"])
            if project["link"]:
                st.markdown(f"[View project]({project['link']})")


def render_experience() -> None:
    section_title("Experience")
    for item in experience:
        st.markdown(f"**{item['role']} - {item['org']}**")
        st.caption(item["time"])
        for bullet in item["bullets"]:
            st.write(f"- {bullet}")
        st.write("")


def render_education() -> None:
    section_title("Education")
    for item in education:
        st.markdown(f"**{item['degree']} - {item['school']}**")
        st.caption(item["time"])
        st.write(item["notes"])
        st.write("")


def render_certifications() -> None:
    section_title("Certifications")
    cols = st.columns(2)
    for idx, cert in enumerate(certifications):
        with cols[idx % 2]:
            if cert["image"].exists():
                st.image(cert["image"], use_column_width=True)
            st.markdown(f"**{cert['title']}**")
            st.markdown(f"[View badge]({cert['link']})")


def render_achievements() -> None:
    section_title("Honors and Awards")
    for item in achievements:
        st.write(f"- {item}")


def render_writeups() -> None:
    section_title("Writeups")
    for item in writeups:
        st.markdown(f"**{item['title']}**")
        st.write(item["summary"])
        if item["path"].exists():
            st.markdown(item["path"].read_text(encoding="utf-8"))
            st.download_button(
                label="Download writeup",
                data=item["path"].read_bytes(),
                file_name=item["path"].name,
                mime="text/markdown",
            )
        else:
            st.write("Writeup file not found.")

def render_contact(resume_bytes: bytes | None) -> None:
    section_title("Contact")
    st.write("Email: kismatkunwar89@gmail.com")
    st.write("LinkedIn: https://www.linkedin.com/in/kunwarkismat/")
    st.write("GitHub: https://github.com/kismatkunwar89")
    if resume_bytes:
        st.download_button(
            label="Download Resume",
            data=resume_bytes,
            file_name="Kismat_Kunwar_Resume.pdf",
            mime="application/pdf",
        )


def main() -> None:
    st.markdown(
        """
        <style>
            .main {
                padding-left: 3rem;
                padding-right: 3rem;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )

    top_cols = st.columns([2, 1])
    with top_cols[0]:
        st.title("Kismat Kunwar")
        st.subheader("Cyber Security Graduate Student")
        st.write(about_text)
        st.write("Based in West Haven, CT. Interested in DFIR, EDR, and network defense.")
        st.markdown(
            "[GitHub](https://github.com/kismatkunwar89) | "
            "[LinkedIn](https://www.linkedin.com/in/kunwarkismat/) | "
            "[Email](mailto:kismatkunwar89@gmail.com)"
        )
    with top_cols[1]:
        if profile_path.exists():
            st.image(profile_path, use_column_width=True, caption="Kismat Kunwar")

    st.divider()
    render_skills()

    st.divider()
    st.markdown("#### About")
    st.write(about_text)

    st.divider()
    render_projects()

    st.divider()
    render_experience()

    st.divider()
    render_education()

    st.divider()
    render_certifications()

    st.divider()
    render_achievements()

    st.divider()
    render_writeups()

    st.divider()
    resume_bytes = resume_path.read_bytes() if resume_path.exists() else None
    render_contact(resume_bytes)


if __name__ == "__main__":
    main()
