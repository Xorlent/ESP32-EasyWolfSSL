# Performance Benchmarks

This document compares the program space and memory usage between native WiFiClientSecure and WolfSSL implementations.

## Testing Environment

All benchmark results are based on the following environment:
- **Arduino IDE**: 2.3.7
- **ESP32 Board Library**: 3.3.7
- **NTP Library**: 1.7.1
- **WolfSSL Library**: 5.8.4
- **Hardware**: Generic ESP-WROOM-32 Development Board

---

## Test 1: SimpleHTTPS.ino

This test uses the SimpleHTTPS.ino sketch, which skips certificate validation and does not use the NTP library or time synchronization.

### WiFiClientSecure (Native)

**Sketch Size:** 660,315 bytes (compressed)

**Memory Usage:**

| Phase | Free Heap | Min Free Heap | Free Stack |
|-------|-----------|---------------|------------|
| Before HTTPS Request | 229,032 bytes | 225,468 bytes | 6,300 bytes |
| After TLS Connection | 226,684 bytes | 225,468 bytes | 6,256 bytes |
| After HTTPS Request | 228,060 bytes | 172,940 bytes | 4,508 bytes |

### WolfSSL

**Sketch Size:** 775,280 bytes (compressed)

**Memory Usage:**

| Phase | Free Heap | Min Free Heap | Free Stack |
|-------|-----------|---------------|------------|
| Before HTTPS Request | 228,372 bytes | 224,808 bytes | 6,300 bytes |
| After TLS Connection | 228,236 bytes | 224,808 bytes | 6,176 bytes |
| After HTTPS Request | 227,200 bytes | 191,184 bytes | 5,148 bytes |

### Comparison

| Metric | WiFiClientSecure | WolfSSL | Difference |
|--------|------------------|---------|------------|
| Sketch Size | 660,315 bytes | 775,280 bytes | +114,965 bytes (17.4% larger) |
| Min Free Heap (lowest point) | 172,940 bytes | 191,184 bytes | +18,244 bytes (10.5% more available) |

---

## Test 2: SecureHTTPS.ino

This test uses the SecureHTTPS.ino sketch, which includes the Let's Encrypt root certificate and uses the NTP library to perform time synchronization.

### WiFiClientSecure (Native)

**Sketch Size:** 672,370 bytes (compressed)

**Memory Usage:**

| Phase | Free Heap | Min Free Heap | Free Stack |
|-------|-----------|---------------|------------|
| Before HTTPS Requests | 221,912 bytes | 219,308 bytes | 6,172 bytes |
| After TLS Connection | 219,544 bytes | 219,276 bytes | 6,160 bytes |
| After Second TLS Connection | 219,212 bytes | 158,884 bytes | 4,336 bytes |
| After All HTTPS Requests | 221,344 bytes | 158,284 bytes | 3,452 bytes |

### WolfSSL

**Sketch Size:** 786,923 bytes (compressed)

**Memory Usage:**

| Phase | Free Heap | Min Free Heap | Free Stack |
|-------|-----------|---------------|------------|
| Before HTTPS Requests | 221,404 bytes | 218,796 bytes | 6,172 bytes |
| After TLS Connection | 221,244 bytes | 218,796 bytes | 6,080 bytes |
| After Second TLS Connection | 221,136 bytes | 181,264 bytes | 5,052 bytes |
| After All HTTPS Requests | 220,728 bytes | 181,240 bytes | 4,812 bytes |

### Comparison

| Metric | WiFiClientSecure | WolfSSL | Difference |
|--------|------------------|---------|------------|
| Sketch Size | 672,370 bytes | 786,923 bytes | +114,553 bytes (17.0% larger) |
| Min Free Heap (lowest point) | 158,284 bytes | 181,240 bytes | +22,956 bytes (14.5% more available) |

---

## Summary

### Program Space

WolfSSL requires approximately **17% more program space** than the native WiFiClientSecure library across both test scenarios:
- SimpleHTTPS: +114,965 bytes (17.4% increase)
- SecureHTTPS: +114,553 bytes (17.0% increase)

### Memory Usage

Despite the larger program size, **WolfSSL demonstrates superior runtime memory efficiency**:
- SimpleHTTPS: 18,244 bytes more free heap available (10.5% improvement)
- SecureHTTPS: 22,956 bytes more free heap available (14.5% improvement)

### Key Findings

1. **Trade-off**: WolfSSL trades increased flash storage (~115KB) for better runtime memory management
2. **Heap Efficiency**: WolfSSL maintains significantly more free heap during TLS operations, reducing the risk of memory-related crashes
3. **Stack Usage**: WolfSSL shows more conservative stack usage, with higher free stack values during operations
4. **Consistency**: The performance characteristics are consistent across both simple and complex scenarios

### Recommendation

WolfSSL is recommended for applications where:
- Runtime stability and memory availability are critical
- The ESP32 has sufficient flash storage (the ~115KB increase is typically acceptable)
- Complex TLS operations or multiple concurrent connections are needed

The native WiFiClientSecure may be preferred when:
- Flash storage is at a premium
- The application has simpler TLS requirements
- Maximum program space must be reserved for application logic
