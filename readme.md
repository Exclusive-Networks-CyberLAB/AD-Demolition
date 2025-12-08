# CyberLAB AD Demolition

A fully automated, configuration-driven Active Directory lab deployment tool designed for cybersecurity training, demos, attack simulations, and PoC environments.

This project lets you deploy a complete AD domain structure—OUs, users, groups, and misconfigurations—in minutes using a simple JSON + CSV configuration model. It also adds fake workstation and server objects to the domain for added realism and fuller dashboards in SIEM / EDR tools.

---

## 🚀 Features

### ✔ Automated AD Lab Deployment
- Creates full OU structure  
- Creates lab security groups  
- Imports users from CSV  
- Assigns baseline group memberships  
- Enforces password + lockout policies per profile  
- Generates fake workstation & server objects (directory-only “endpoints”)  
- Supports multiple profiles (secure → misconfigured → chaos)

---

## ✔ Misconfiguration Profiles (1–4)

| Profile | Name | Purpose |
|--------|------|----------|
| **1** | Secure Baseline | Clean enterprise-ready AD with hardened password policies |
| **2** | Real-World Mess | Weak configurations seen in customer environments |
| **3** | Attack Playground | Highly misconfigured domain ideal for BloodHound/attack-path demos |
| **4** | DC Chaos Mode ⚠️ | Profile 3 + domain controller protocol/service hard breaks |

Each profile is fully defined in `ad-config.json` and applies:
- Password policies  
- Misconfiguration modules  
- DC-level weakening (Profile 4)  
- Identity risks (Profiles 3–4)

---

## 🧩 Config-Driven Architecture

### `ad-config.json`
Defines:

- OU structure  
- Security groups  
- User roles  
- All Misconfig IDs  
- Profile-level logic  
- Fake endpoint generation (`FakeEndpoints` block)

### `users.csv`
Defines:

- SamAccountName  
- First/Last name  
- Display name  
- OU location  
- Group memberships  
- Service account flags  

Because everything is config-driven, you can quickly swap datasets or create variants for different workshops and demos.

---

## 🔥 Misconfiguration Modules

### User & Group Misconfigs
- `PasswordNeverExpires` on service accounts  
- Privileged users with weak settings  
- Overbroad local admin rights on workstations and servers  
- Shared admin accounts  
- Disabled-but-privileged stale accounts  
- Helpdesk → Domain Admins  
- Service accounts → Domain Admins  

### Identity Risks
Designed to light up identity / AD posture tools (e.g. Falcon Identity):

- Kerberos pre-authentication disabled on a service account (AS-REP roastable)
- Weak SPN service account with:
  - SQL-style SPN
  - Password never expires
  - Weak/common password

Maps directly to risks like:

- Stealthy Privileges  
- Attack Paths to Privileged Accounts  
- Poorly Protected Accounts with SPNs  

---

## ⚡ DC Chaos Mode (Profile 4)

Adds extreme domain controller misconfigurations:

- Enable SMBv1  
- Disable SMB signing  
- Enable LLMNR & NetBIOS  
- Disable LDAP signing & channel binding  
- Enable legacy NTLM  
- Disable Windows Firewall  
- Weaken Microsoft Defender  
- Shorten event log retention  
- Open inbound SMB/RPC  
- Weaken SYSVOL permissions  

For demo labs only — never production.

---

## 🖥 Fake Endpoint Fleet

To make the lab *look* like a much larger domain:

### Automatically generates:
- Workstations (`WKSTN-0001` → `WKSTN-000X`)
- Servers (`SRV-0001` → `SRV-000X`)

These show up in identity / AD dashboards, helping support:

- Lateral movement demonstrations  
- Attack-path visualisation  
- “Large enterprise” look without actual VMs  

Configured via:

```json
"FakeEndpoints": {
  "Enable": true,
  "WorkstationCount": 50,
  "ServerCount": 10,
  "NamingPrefixWorkstations": "WKSTN",
  "NamingPrefixServers": "SRV"
}
```

---

## ▶ Usage

### 1. Prepare a test domain
Use only in isolated CyberLAB/CloudShare domains.

### 2. Run:

```
.\New-CyberLAB-AdLab.ps1 -Profile 1
```

Or choose interactively.

### Profiles

```
Profile 1 = Secure Baseline
Profile 2 = Real-World Mess
Profile 3 = Attack Playground
Profile 4 = DC Chaos Mode
```

---

## 📁 Folder Structure

```
CyberLAB-AD-Demolition/
│
├── New-CyberLAB-AdLab.ps1
└── Configs/
    └── Default/
        ├── ad-config.json
        └── users.csv
```

---

## 🛡 Warning

This environment is intentionally vulnerable.  
Do **not** run on production domains.  
Do **not** connect to corporate VPNs.  
Isolated labs only.

---

## 🤝 Contributing

You can contribute:

- New misconfig modules  
- Extra profiles  
- Larger user datasets  
- Detection/hunting guides  
- Improvements to error-handling  

---

## 📄 License

MIT License — free for labs, demos, training.
