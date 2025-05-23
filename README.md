# WiFi Handshake Capture Tool

<div align="center">
  
[![GPLv3 License](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE.md)
[![Ethical Use](https://img.shields.io/badge/INTENDED_USE-Pentesting_Research-red)](https://github.com/Electro-Gamma/esp32-handshake-capture/blob/main/README.md#ethical-use)
[![Platform](https://img.shields.io/badge/Platform-ESP32-important)](https://github.com/Electro-Gamma/esp32-handshake-capture/blob/main/README.md#requirements)
[![Warning](https://img.shields.io/badge/WARNING-Legal_Restrictions-yellow)](https://github.com/Electro-Gamma/esp32-handshake-capture/blob/main/README.md#legal-disclaimer)


</div>

## ⚠️ Legal Disclaimer

This software is provided strictly for educational and authorized testing purposes only.  
Unauthorized use of this tool against networks you do not own or have written permission to test is illegal in most jurisdictions.  
The developers are not responsible for any misuse, damage, or legal consequences.

---

## Features

- Captures WPA/WPA2 EAPOL 4-way handshakes
- Saves captured data in PCAP format
- Web interface to download handshakes
- Portable and lightweight with ESP32
- Passive monitoring (no injection required)
- Works with tools like Wireshark, Aircrack-ng, Hashcat (after conversion)

---

## Requirements

- ESP32 Development Board (e.g., DevKit v1)
- USB cable (Micro-USB or USB-C depending on your board)
- Arduino IDE or PlatformIO
- Serial Monitor (115200 baud)
- WiFi network you are authorized to test

---

## Flashing Instructions

### Option 1: Arduino IDE

1. Install ESP32 board support:
   - File → Preferences → Additional Board URLs:
     ```
     https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
     ```
2. Open Boards Manager and install "ESP32"
3. Load `esp32-handshake-capture.ino`
4. Select:
   - Board: ESP32 Dev Module
   - Port: Your correct COM/tty port
5. Click "Upload"

### Option 2: PlatformIO (VS Code)

```bash
git clone https://github.com/Electro-Gamma/esp32-handshake-capture.git
cd esp32-handshake-capture
pio run --target upload
```

---

## Running the Tool

1. Open a serial monitor at 115200 baud.
2. The ESP32 will scan for nearby WiFi networks.
3. Select the target network by its SSID/BSSID.
4. The handshake is captured passively.
5. ESP32 saves the handshake as a `.pcap` file.
6. Connect to the ESP32's web interface to download the capture.

---

## Output

Captured handshakes are stored in `.pcap` format and compatible with:
- Wireshark
- aircrack-ng
- hcxpcapngtool / hashcat

---

## Usage Policy

This tool is intended for:
- Security researchers
- Cybersecurity training labs
- Authorized penetration testers
- Educational demonstrations

You must:
- Use only on networks you own or have explicit permission to test
- Follow local, national, and international laws
- Accept full responsibility for all usage

---

## Legal Notice

Be aware of applicable laws that may govern or restrict the use of this tool, including but not limited to:
- Computer Fraud and Abuse Act (CFAA)
- General Data Protection Regulation (GDPR)
- Digital Millennium Copyright Act (DMCA)
- National and regional cybercrime laws

The authors are not liable for illegal or unethical use.

---

## License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**.  
See the [LICENSE](LICENSE.md) file for full terms.

---

## Contact

- GitHub: [Electro-Gamma](https://github.com/Electro-Gamma)

---

Stay ethical. Use responsibly.
