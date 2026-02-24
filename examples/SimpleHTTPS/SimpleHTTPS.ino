/*
 * SimpleHTTPS.ino - Simple HTTPS GET request example
 * 
 * This example demonstrates how to use ESP32-EasyWolfSSL library
 * as a drop-in replacement for WiFiClientSecure.
 * 
 * Works with HTTPClient just like the standard WiFiClientSecure
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

// WiFi credentials
const char* ssid = "Your_SSID_Here";
const char* password = "WiFi_Password_Here";

// Test server (you can use any HTTPS server)
const char* test_url = "https://www.howsmyssl.com/a/check";

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
    Serial.println("\n\nESP32-EasyWolfSSL - Simple HTTPS Example (WolfSSL)");
#else
    Serial.println("\n\nESP32 - Simple HTTPS Example (WiFiClientSecure)");
#endif
    Serial.println("==========================================\n");
    
#ifdef USE_WOLFSSL
    // Optional: Enable debug output
    //WolfSSLClient::setDebug(true);
#endif
    
    // Connect to WiFi
    Serial.print("Connecting to WiFi");
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println(" Connected!");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
    
    // Show memory before HTTPS request
    printMemoryStats("Before HTTPS Request");
    
    // Make HTTPS request
    makeHTTPSRequest();
    
    // Show memory after HTTPS request
    printMemoryStats("After HTTPS Request");
}

void loop() {
    // Nothing to do here
    delay(10000);
}

void makeHTTPSRequest() {
    // Create secure client (WolfSSL or WiFiClientSecure based on config)
    SecureClient client;
    
    // For testing, you can skip certificate verification
    // In production be sure to use proper certificates
    client.setInsecure();
    
    // Set a CA certificate for proper verification:
    // client.setCACert(root_ca_cert);
    
    // Create HTTPClient
    HTTPClient https;
    
    Serial.println("\n[HTTPS] Making request...");
    
    // Configure HTTPClient to use our secure client
    if (https.begin(client, test_url)) {
        
        // Show memory during connection
        printMemoryStats("After TLS Connection Established");
        
        // Make GET request
        Serial.println("[HTTPS] GET...");
        int httpCode = https.GET();
        
        // Check response
        if (httpCode > 0) {
            Serial.printf("[HTTPS] Response code: %d\n", httpCode);
            
            if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY) {
                String payload = https.getString();
                Serial.println("\n[HTTPS] Response:");
                Serial.println("----------------------------------------");
                Serial.println(payload);
                Serial.println("----------------------------------------");
            }
            
#ifdef USE_WOLFSSL
            // Get connection info (WolfSSL only)
            Serial.println("\n[HTTPS] Connection info:");
            Serial.printf("  Protocol: %s\n", client.getProtocolVersion());
            Serial.printf("  Cipher: %s\n", client.getCipherSuite());
#endif
        } else {
            Serial.printf("[HTTPS] GET failed, error: %s\n", 
                         https.errorToString(httpCode).c_str());
        }
        
        https.end();
    } else {
        Serial.println("[HTTPS] Unable to connect");
    }
}
