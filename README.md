# QuickLinIR

### QuickLinIR - Quick Linux Initial Incident Response

**QuickLinIR** is a lightweight CLI utility designed to assist with **rapid initial incident response and compromise triage on Linux systems**.

When a Linux system is suspected of being compromised, the first priority is to quickly establish **visibility into what is happening on the host**. QuickLinIR performs a series of system-level inspections to help identify potentially suspicious processes, network activity, persistence mechanisms, privileged accounts, unauthorized SSH access, services, kernel modules, malicious / vulnerable third-party libraries installed on the system.

The goal is simple:

> **Suspect a compromise?  Run QuickLinIR and get visibility into your system.**

QuickLinIR is intended to serve as an **initial triage tool**. Its findings should be treated as indicators requiring further investigation rather than definitive proof of compromise.

---

## Features

QuickLinIR provides a collection of focused inspection modules covering several areas commonly relevant during initial Linux incident response.

| Module                   | Description                                                                                                                                                                                                                                                                             |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Network Analysis**     | Inspect active network connections, including listening services and established connections, and provide contextual information about the remote peers such as organization/ASN details. Identifies unexpected or potentially malicious network activity through ip reputation checks. |
| **Process Analysis**     | Review currently running processes, including files opened by each process.                                                                                                                                                                                                             |
| **Environment Analysis** | Inspect all user accounts on the system , and currently logged-in users.                                                                                                                                                                                                                |
| **Service Analysis**     | Review system services, including their status, and the command it executes.                                                                                                                                                                                                            |
| **Cron Jobs**            | Enumerate all cron jobs.                                                                                                                                                                                                                                                                |
| **Startup Scripts**      | Identify startup scripts and potential boot-time persistence mechanisms.                                                                                                                                                                                                                |
| **Root Accounts**        | Enumerate accounts with root-level privileges.                                                                                                                                                                                                                                          |
| **SSH Authorized Keys**  | Enumerate users' SSH authorized keys.                                                                                                                                                                                                                                                   |
| **Kernel Modules**       | List loaded kernel modules, including their status and author information and the description of the module.                                                                                                                                                                            |
| **Library Scanning**     | Inspect installed Python liberaries / Ruby Gems , and identify vulnerable / malicious ones.                                                                                                                                                                                             |

---

## Why QuickLinIR?

During an incident, time matters.

A potentially compromised system can contain a large amount of information, and manually checking every relevant location can be time-consuming. QuickLinIR provides a **single, lightweight command-line interface** for performing a rapid first-pass inspection of important system areas.

It can help answer questions such as:

- What processes are currently running and what files are they opening ?

- What services are listening, what established connections exist, and information about remote peers (organization name/ASN) and whether the peer is malicious or suspicious ?
   
- What services exist on the system, and their status and what executables do they run ?

- what users accounts exist on the system and which users are currently logged in ? 

- Are there suspicious persistence mechanisms ?
   
- What cron jobs are configured ?
   
- What scripts execute during system startup / user logon ?
 
- Which users have root-level privileges ?
   
- Are there unexpected SSH authorized keys ?
   
- What kernel modules are currently loaded, ? ( including their descriptions and authors ) 
   
- What third-party libraries are installed and whether they are malicious or vulnerable ?
   

QuickLinIR does not replace a full forensic investigation. Instead, it helps investigators and administrators quickly establish an initial understanding of the system and determine where deeper analysis may be necessary.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/o-sec/QuickLinIR.git
cd QuickLinIR
```

Install required libraries:

```shell
pip install -r requirements.txt
```

Make the script executable:

```shell
chmod +x quicklinir.py
```


---
## Usage

```text
usage: quicklinir.py [-h] [-a] [-n] [-p] [-e] [-s] [-c] [-u] [-r] [-t] [-k] [-l]

Quick Linux Initial Incident Response.

options:
  -h, --help            show this help message and exit
  -a, --all             audit everything ( default )
  -n, --network         audit network connections
  -p, --processes       audit processes
  -e, --environment     audit the environment
  -s, --services        audit services
  -c, --cronjobs        list all users cronjobs
  -u, --startup         list startup scripts
  -r, --roots           list all root accounts
  -t, --trustedsshkeys  list all users ssh authorized keys
  -k, --kernelmodules   list loaded kernel modules
  -l, --scanlibs        scan installed libraries (PyPI Libs/ RubyGems)

```


> For the most comprehensive results, running the tool with elevated privileges may be required !
> For ip-reputation scanning add you **virustotal** API Key to `config.py` :
> 
> `VIRUS_TOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"` 
> 




**Run a Full Initial Response Audit**

Run all available inspection modules:

```bash
sudo quicklinir.py --all
```

The `--all` option is also the default behavior

```bash
sudo quicklinir.py
```

This provides a broad overview of the system and can serve as a starting point for further investigation.


#### Individual Modules



**Network Analysis**

Inspect network connections:

```bash
-n / --network
```

Useful for identifying unexpected connections and other network activity that may require investigation.



**Process Analysis**

Inspect running processes:

```bash
-p / --processes
```

This module can help identify unexpected processes or processes that warrant further investigation.



**Environment Analysis**

Inspect the system environment:

```bash
-e / --environment
```

Environment information can provide useful context during incident response and help identify unexpected configuration.


**Service Analysis**

Inspect system services:

```bash
-s / --services
```

Unexpected or unfamiliar services can be relevant during compromise investigations and should be reviewed in context.


**Cron Jobs**

Enumerate user cron jobs:

```bash
-c / --cronjobs
```

Cron jobs are a common mechanism for scheduled execution and can be relevant when investigating potential persistence.


**Startup Scripts**

Inspect startup scripts:

```bash
-u / --startup
```

This module enumerates startup scripts and executables that may be configured to run automatically during system boot or user login, helping identify potential persistence mechanisms.


**Root Accounts**

Enumerate root accounts:

```bash
-r / --roots
```

This can help identify accounts with root-level access.


**SSH Authorized Keys**

Inspect SSH authorized keys:

```bash
-t / --trustedsshkeys
```

This module enumerates SSH authorized keys associated with each user account, helping identify potentially unauthorized or unexpected SSH access mechanisms.


**Loaded Kernel Modules**

List currently loaded kernel modules:

```bash
-k / --kernelmodules
```


This module provides visibility into kernel modules currently loaded on the system.


**Installed Library Scanning**

Scan installed third-party libraries:

```bash
-l / --scanlibs
```

Currently supported package ecosystems include:

- Python **PyPI** packages
- Ruby **RubyGems**

This can help identify vulnerable or malicious installed third-party libraries.



### Examples

Run a complete system inspection

```bash
sudo quicklinir.py --all
```

Investigate network activity

```bash
sudo quicklinir.py --network
```

Review running processes

```bash
sudo quicklinir.py --processes
```

Investigate potential persistence

```bash
sudo quicklinir.py --cronjobs --startup
```

Review privileged access

```bash
sudo quicklinir.py --roots --trustedsshkeys
```

Inspect services and kernel modules

```bash
sudo quicklinir.py --services --kernelmodules
```


## Quick Demo Video

[![Demo](https://img.youtube.com/vi/p0LYlQymmbY/0.jpg)]([p0LYlQymmbY](https://youtu.be/p0LYlQymmbY))





---
## Disclaimer

QuickLinIR is intended for **authorized security auditing, defensive security, incident response, digital investigation

Only use QuickLinIR on systems that you own or have explicit authorization to inspect.

The presence of an item identified by QuickLinIR does not necessarily indicate malicious activity or compromise. Findings should be evaluated within the context of the system and investigated further before drawing conclusions.

The author is not responsible for misuse of this tool or for any damage resulting from its use.
