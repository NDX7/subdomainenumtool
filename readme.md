# SUBFIND
**SUBFIND** 
---

## 🛠 Methodology

### {1} Discovery & Reconnaissance
* **Active Fuzzing:** Performs basic fuzzing using known wordlists to identify hidden subdomains.
    > *Current Status: Integrated via `ffuf` (Optimization in progress to address latency).*
* **Passive API Aggregation:** Instead of direct implementation, the tool utilizes `subfinder` to pull data from:
    * **crt.sh** (Certificate Transparency)
    * **Censys** & **VirusTotal**
    * **Wayback Machine**
* **Web Crawling (Pending):** Feature to extract subdomains by crawling the target website's frontend.


### {3} Presentation & Output
* **Sorting:** Automated deduplication and logical ordering of results.
* **Beautification:** Polished output formatting for better readability and reporting. 
    > *Current Status: Feature nearly complete.*

---

## 📊 Development Roadmap

| Feature | Status |
| :--- | :--- |
| Basic Fuzzing (ffuf) | ✅ Done |
| API Integration (subfinder) | ✅ Done |
| Sorting & Formatting | ✅ Done |

---

*Generated for SUBFIND Project Documentation*
