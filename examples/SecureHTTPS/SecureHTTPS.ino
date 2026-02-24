/*
 * SecureHTTPS.ino - HTTPS with certificate verification
 * 
 * This example shows how to use proper certificate verification
 * instead of setInsecure().
 * 
 * Required Libraries:
 *  - WolfSSL (install from Library Manager)
 *  - NTP by Stefan Staub (install from Library Manager)
 * 
 * Configuration: Comment/uncomment USE_WOLFSSL to compare implementations
 */

// ============================================================
// CONFIGURATION: Choose TLS implementation
// ============================================================
#define USE_WOLFSSL  // Comment this line to use native WiFiClientSecure
// ============================================================

#include <WiFi.h>
#include <HTTPClient.h>

#ifdef USE_WOLFSSL
  #include <WolfSSLClient.h>
  typedef WolfSSLClient SecureClient;
#else
  #include <WiFiClientSecure.h>
  typedef WiFiClientSecure SecureClient;
#endif

#include <NTP.h>
#include <time.h>

// WiFi credentials
const char* ssid = "Your_SSID_Here";
const char* password = "WiFi_Password_Here";

WiFiUDP wifiUdp;
NTP ntp(wifiUdp);

// Root CA certificate for Let's Encrypt (ISRG Root X1)
const char* root_ca = \
"-----BEGIN CERTIFICATE-----\n" \
"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\n" \
"-----END CERTIFICATE-----\n";

// Prints memory statistics
void printMemoryStats(const char* label) {
    Serial.printf("\n[MEMORY] %s\n", label);
    Serial.printf("  Free Heap: %u bytes\n", ESP.getFreeHeap());
    Serial.printf("  Min Free Heap: %u bytes\n", ESP.getMinFreeHeap());
    Serial.printf("  Free Stack: %u bytes\n", uxTaskGetStackHighWaterMark(NULL));
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
#ifdef USE_WOLFSSL
    Serial.println("\n\nESP32-EasyWolfSSL - Secure HTTPS Example (WolfSSL)");
#else
    Serial.println("\n\nESP32 - Secure HTTPS Example (WiFiClientSecure)");
#endif
    Serial.println("==========================================\n");
    
#ifdef USE_WOLFSSL
    // Optional: Enable debugging
    //WolfSSLClient::setDebug(true);
#endif
    
    // Connect to WiFi
    Serial.print("Connecting to WiFi");
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(1000);
        Serial.print(".");
    }
    Serial.println(" Connected!");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
    
    // Synchronize time using NTP (required for certificate validation)
    Serial.println("\nSynchronizing time with NTP server...");
    ntp.begin();
    ntp.update();
    delay(500);
    Serial.print("Time (NTP library): ");
    Serial.println(ntp.formattedTime("%Y-%m-%d %H:%M:%S"));
    
    // Set the system clock from NTP (required for WolfSSL certificate validation)
    time_t epoch_time = ntp.epoch();
    struct timeval tv = { .tv_sec = epoch_time, .tv_usec = 0 };
    settimeofday(&tv, nullptr);
    
    // Verify system clock is now set
    time_t now = time(nullptr);
    struct tm timeinfo;
    gmtime_r(&now, &timeinfo);
    Serial.print("Time (system clock): ");
    Serial.printf("%04d-%02d-%02d %02d:%02d:%02d (epoch: %ld)\n", 
                  timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                  timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec, now);
    
    // Show memory before HTTPS requests
    printMemoryStats("Before HTTPS Requests");
    
    // Make secure HTTPS request
    makeSecureRequest();
    
    // Show memory after all HTTPS requests
    printMemoryStats("After All HTTPS Requests");
}

void loop() {
    delay(10000);
}

void makeSecureRequest() {
    SecureClient client;
    
    // Set CA certificate for verification
    client.setCACert(root_ca);
    
    HTTPClient https;
    
    // Try a few different HTTPS sites we know user Let's Encrypt
    const char* test_urls[] = {
        "https://www.howsmyssl.com/a/check",
        "https://pantheon.io",
        nullptr
    };
    
    for (int i = 0; test_urls[i] != nullptr; i++) {
        Serial.printf("\n[HTTPS] Testing: %s\n", test_urls[i]);
        Serial.println("----------------------------------------");
        
        if (https.begin(client, test_urls[i])) {
            // Show memory during connection
            printMemoryStats("After TLS Connection Established");
            
            int httpCode = https.GET();
            
            if (httpCode > 0) {
                Serial.printf("Response code: %d\n", httpCode);
                
                if (httpCode == HTTP_CODE_OK) {
                    String payload = https.getString();
                    Serial.println("\nResponse:");
                    // Print first 500 characters
                    if (payload.length() > 500) {
                        Serial.println(payload.substring(0, 500));
                        Serial.println("... (truncated)");
                    } else {
                        Serial.println(payload);
                    }
                }
                
#ifdef USE_WOLFSSL
                // Show connection info (WolfSSL only)
                Serial.println("\nConnection info:");
                Serial.printf("  Protocol: %s\n", client.getProtocolVersion());
                Serial.printf("  Cipher: %s\n", client.getCipherSuite());
#endif
            } else {
                Serial.printf("GET failed: %s\n", 
                             https.errorToString(httpCode).c_str());
            }
            
            https.end();
        } else {
            Serial.println("Unable to connect");
        }
        
        Serial.println("----------------------------------------\n");
        delay(1000);
    }
}
