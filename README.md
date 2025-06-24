# SuspiciousProcessDetector 🔍

A standalone **Java class** to detect and flag potentially **suspicious or malicious processes** running on Windows or Linux systems.  
Ideal for security analysts, CEH trainees, or SOC/NOC environments.

---

## 🎯 Why I built this

During my early training in SOC and CEH preparation, I noticed how often attackers use **built-in OS tools** like `powershell`, `rundll32`, or `wscript` to move stealthily.  
I was once debugging a system that kept getting reinfected — and it turned out a tiny scheduled script was re-downloading payloads using `mshta.exe`. That experience pushed me to write this scanner.

This tool automates basic **process inspection** and flags anything suspicious based on known bad indicators — no agents, no installs.

---

## 🚀 Features

- ✅ Cross-platform: works on **Windows** (`tasklist`) and **Linux/macOS** (`ps`)
- 🚨 Built-in keyword detection: flags known bad tools like:
  - `mimikatz`, `powershell`, `nc.exe`, `wscript`, `mshta`, `rundll32`, etc.
- 🔍 Fast scanning using pure Java
- 💡 Easily extendable list of suspicious patterns

---

## 📦 How to Run

### 1. Compile:
```bash
javac SuspiciousProcessDetector.java
```

### 2. Run:
```bash
java SuspiciousProcessDetector
```

### Example Output:
```
🔍 Suspicious Process Detector - Advanced Mode
---------------------------------------------
🚨 Suspicious processes detected:
[ALERT] powershell.exe -nop -w hidden -enc ZQBlAHAA
[ALERT] rundll32.exe \malicious.dll,entry
```

---

## 🧠 Use Cases

- CEH/Pentest labs
- Red/Blue Team simulations
- Quick forensic triage on compromised systems
- Educational tools for malware process hunting

---

## 🔧 Extending It

You can edit this array in the code to add more detection rules:
```java
private static final String[] SUSPICIOUS_KEYWORDS = {
    "mimikatz", "nc.exe", "cmd.exe /c", "powershell", ...
};
```

---

## 🛡️ Disclaimer

This tool is for **educational and defensive purposes only**.  
Always review flagged processes manually before taking any action.

---

## 👨‍💻 Author

Mohammad Ali — Security enthusiast & developer  
GitHub: https://github.com/GTAexcess
