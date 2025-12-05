# CyberLAB AD Lab Builder

A fully automated, configuration‑driven Active Directory lab deployment tool designed for cybersecurity training, demos, attack simulations, and PoC environments.

This project lets you deploy a complete AD domain structure—OUs, users, groups, and misconfigurations—in minutes using a simple JSON + CSV configuration model.

---

## 🚀 Features

### ✔ Automated AD Lab Deployment
- Creates full OU structure  
- Creates lab security groups  
- Imports users from CSV  
- Assigns baseline group memberships  
- Enforces password + lockout policies per profile  
- Supports multiple profiles (secure → misconfigured → chaos)

### ✔ Misconfiguration Profiles (1–4)

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

---

## 🧩 Config-Driven Architecture

### **ad-config.json**
Defines:
- OU structure  
- Security groups  
- User roles  
- All Misconfig IDs  
- Profile-level logic  

### **users.csv**
Defines:
- SamAccountName  
- First/Last name  
- Display name  
- OU location  
- Group memberships  
- Service account flags  

---

## 🔥 Misconfiguration Modules

### User & Group Misconfigs
- PasswordNeverExpires on service accounts  
- Privileged users with weak settings  
- Overbroad local admin rights  
- Shared admin accounts  
- Disabled-but-privileged stale accounts  
- Helpdesk → Domain Admins  
- Service accounts → Domain Admins  

### DC Chaos Mode (Profile 4)
- Enable SMBv1  
- Disable SMB signing  
- Enable LLMNR  
- Enable NetBIOS  
- Weaken LDAP security  
- Enable legacy NTLM  
- Disable Windows Firewall  
- Weaken Microsoft Defender  
- Reduce event log retention  
- Open inbound SMB/RPC  
- Weaken SYSVOL permissions  

---

## ▶ Usage

### 1. Prepare a test domain
Use in:
- CloudShare / CyberLAB  
- Isolated VM environment  
- Non-production AD labs  

### 2. Run the script

```powershell
.\New-CyberLAB-AdLab.ps1 -Profile 1
```

Or choose interactively if unspecified.

### Profile Examples

```powershell
.\New-CyberLAB-AdLab.ps1 -Profile 1   # Secure baseline
.\New-CyberLAB-AdLab.ps1 -Profile 2   # Real-world mess
.\New-CyberLAB-AdLab.ps1 -Profile 3   # Attack playground
.\New-CyberLAB-AdLab.ps1 -Profile 4   # Domain Controller Chaos Mode
```

---

## 📁 Folder Structure

```
CyberLAB-ADLab/
│
├── New-CyberLAB-AdLab.ps1
└── Configs/
    └── Default/
        ├── ad-config.json
        └── users.csv
```

---

## 🛡 Warning

This environment is **intentionally vulnerable**.  
Use ONLY in isolated lab or demo environments.

---

## 🤝 Contributing

Pull requests welcome!  
You can contribute:
- New misconfiguration modules  
- Additional profiles  
- More user datasets  
- Error handling improvements  

---

## 📄 License

MIT License – free to use in labs, demos, and training.
