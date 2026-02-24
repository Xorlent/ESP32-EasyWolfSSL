# Migration Guide: From WiFiClientSecure to ESP32-EasyWolfSSL

This guide helps you migrate existing code from WiFiClientSecure to ESP32-EasyWolfSSL.

## Prerequisites

**Before you begin**, please follow the installation instructions in the [README.md](README.md):
1. Review the [Installation](README.md#installation) section
2. **IMPORTANT**: Follow the [Dependencies](README.md#dependencies) section to install required libraries and configure WolfSSL's `user_settings.h` as described in [Important WolfSSL Configuration](README.md#important-wolfssl-configuration) (required for certificate validation)

Once you've completed the installation and configuration, return here to migrate your code.

## Update Your Code

### Minimal Changes Required

Most code will work with just a header change:

**Before:**
```cpp
#include <WiFiClientSecure.h>

WiFiClientSecure client;
```

**After:**
```cpp
#include <WolfSSLClient.h>

WiFiClientSecure client;  // Accepts original name via typedef
```

**That's it!** The library automatically initializes when you create your first client object.

## Certificate Handling

The certificate methods are the same:

```cpp
// These work identically:
client.setCACert(root_ca);
client.setCertificate(client_cert);
client.setPrivateKey(private_key);
client.setInsecure();
```

## Complete Example: Before and After

### Before (WiFiClientSecure)

```cpp
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>

const char* ssid = "MyWiFi";
const char* password = "MyPassword";

void setup() {
    Serial.begin(115200);
    
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    
    WiFiClientSecure client;
    client.setInsecure();
    
    HTTPClient https;
    https.begin(client, "https://api.example.com/data");
    int code = https.GET();
    if (code > 0) {
        Serial.println(https.getString());
    }
    https.end();
}

void loop() {}
```

### After (ESP32-EasyWolfSSL)

```cpp
#include <WiFi.h>
#include <HTTPClient.h>
#include <WolfSSLClient.h>  // Changed

const char* ssid = "MyWiFi";
const char* password = "MyPassword";

void setup() {
    Serial.begin(115200);
    
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    
    WiFiClientSecure client;
    client.setInsecure();
    
    HTTPClient https;
    https.begin(client, "https://api.example.com/data");
    int code = https.GET();
    if (code > 0) {
        Serial.println(https.getString());
    }
    https.end();
}

void loop() {}
```

**That's it!** Only 1 change needed:
- Include `WolfSSLClient.h` instead of `WiFiClientSecure.h`

## Common Patterns

### Pattern 1: Simple HTTPS with HTTPClient

```cpp
#include <WolfSSLClient.h>

WiFiClientSecure client;
client.setInsecure();

HTTPClient https;
https.begin(client, url);
// ... use as normal
```

### Pattern 2: Secure Connection with CA Cert

```cpp
#include <WolfSSLClient.h>

const char* root_ca = "-----BEGIN CERTIFICATE-----\n...";

WiFiClientSecure client;
client.setCACert(root_ca);  // Validate with supplied root cert

HTTPClient https;
https.begin(client, url);
// ... use as normal
```

### Pattern 3: Mutual TLS (mTLS)

```cpp
#include <WolfSSLClient.h>

const char* root_ca = "...";
const char* client_cert = "...";
const char* client_key = "...";

WiFiClientSecure client;
client.setCACert(root_ca);
client.setCertificate(client_cert);
client.setPrivateKey(client_key);

HTTPClient https;
https.begin(client, url);
// ... use as normal
```

## Troubleshooting

### Common Migration Issues

**"WiFiClientSecure identifier not found"**
- Make sure you're including `WolfSSLClient.h`, which provides the typedef

**Compilation errors about methods not found**
- Check that you've updated all includes. Some files may still include the old header

**Certificate verification failures**
- Ensure you've configured WolfSSL's `user_settings.h` with `FP_MAX_BITS 8192` (see [Dependencies in the README](README.md#dependencies))
- This is the most common issue when migrating code that validates certificates

For additional troubleshooting help, including connection issues, memory problems, and debugging techniques, see the [Troubleshooting section in the README](README.md#troubleshooting).