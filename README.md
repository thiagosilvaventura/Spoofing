<div align="center">
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="JavaScript" />
  <img src="https://img.shields.io/badge/Cybersecurity-000000?style=for-the-badge&logo=security&logoColor=white" alt="Security" />
  <img src="https://img.shields.io/badge/Forensics-4285F4?style=for-the-badge&logo=google-chrome&logoColor=white" alt="Forensics" />
</div>
<br>

# 🎭 Spoofing & Anti-Detect Forensics

A repository housing two client-side JavaScript tools designed for educational cybersecurity research and anti-fraud operations mapping. Both standalone scripts inject floating, glassmorphism-styled UI panels and bypass TrustedHTML restrictions utilizing native DOM creation methods[cite: 4, 5].

## 🛠 Core Modules

### 1. Anti-Detect Spawning Simulator (`Spoofing demonstration`)
A visual simulation engine replicating the behavior of commercial Anti-Detect browsers (such as Multilogin) by procedurally rotating spoofed fingerprint datasets every 10 seconds[cite: 4]. 

* **Canvas Noise Injection:** Simulates randomized payload injection into HTML5 canvas bases[cite: 4].
* **Hardware Spoofing:** Cycles through fabricated WebGL renderers and screen resolutions[cite: 4].
* **Network & Identity:** Rotates User-Agent strings and proxy-pool IP/Geolocation assignments[cite: 4].

### 2. Data Necromancer (`Attributes_view`)
A fingerprint extraction script designed to surface hardware, network, and browser identity attributes heavily utilized by advanced anti-fraud engines (e.g., LexisNexis ThreatMetrix)[cite: 5].

* **Advanced Hashing:** Implements a JavaScript variant of MurmurHash3 to generate unique identifiers for DOM elements[cite: 5].
* **Graphics Fingerprinting:** Generates precise Canvas Hashes, Canvas Color Hashes, and WebGL renderer hashes[cite: 5].
* **Network Interrogation:** Maps HTTP Connection Types and executes an active WebRTC Leak Test to expose true underlying IP geolocation, bypassing proxy layers[cite: 5].
