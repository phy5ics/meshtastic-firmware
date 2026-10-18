// Unit tests for PaxMacTracker in src/modules/PaxMacTracker.h and src/modules/PaxMacTracker.cpp.
//
// The Paxcounter module sniffs surrounding Wi-Fi probe requests and Bluetooth Low Energy advertisements.
// Instead of merely aggregating these into device counts, PaxMacTracker identifies unique MAC addresses,
// identifies whether an address is locally administered (randomized) or universally assigned, performs
// OUI manufacturer lookup for universal hardware identifiers, deduplicates against recently seen devices,
// stages them into an outbound queue, and formats them into text message broadcasts for the mesh network.
//
// The regressions guarded here are:
// 1. Airtime saturation from redundant broadcasts: identical MACs of the same radio type must be suppressed
//    by the recent deduplication cache.
// 2. Cross-technology collision: identical MAC bytes emitted on Wi-Fi and BLE must be tracked separately
//    since MAC namespaces are independent.
// 3. Buffer overflow / formatting corruption: formatMacMessage() must enforce buffer boundaries when
//    generating single or multi-line messages under high detection counts.
// 4. Batch draining and queue discipline: drainPendingMacs() must safely clamp to the requested batch size
//    and preserve remaining queued items in FIFO order.
// 5. False OUI attribution on randomized MACs: locally administered MAC addresses must be classified as
//    "Random" rather than matching pseudo-random prefixes against registered IEEE OUIs.
// 6. OUI binary search precision: known manufacturer OUIs must map to correct vendor strings while
//    unregistered universal addresses cleanly return an empty vendor string.
// 7. Paxcount protobuf serialization fidelity: populatePaxcountDevices() must populate meshtastic_Paxcount
//    with MAC bytes, SniffType enum, and resolved vendor strings, and round-trip cleanly through nanopb.

#include "Arduino.h"
#include "TestUtil.h"
#include "modules/PaxMacTracker.h"
#include <cstring>
#include <pb_decode.h>
#include <pb_encode.h>
#include <unity.h>

static PaxMacTracker tracker;

void setUp(void)
{
    tracker.clear();
}

void tearDown(void)
{
    tracker.clear();
}

void test_record_single_wifi_mac_with_vendor(void)
{
    // Espressif universal OUI 24:0A:C4
    const uint8_t mac[6] = {0x24, 0x0A, 0xC4, 0x78, 0x9A, 0xBC};
    TEST_ASSERT_TRUE(tracker.recordDetectedMac(mac, PAX_SNIFF_WIFI));
    TEST_ASSERT_EQUAL_UINT32(1, tracker.getPendingCount());
    TEST_ASSERT_EQUAL_UINT32(1, tracker.getRecentCount());

    PaxDetectedMac last = {};
    TEST_ASSERT_TRUE(tracker.getLastSeen(last));
    TEST_ASSERT_EQUAL_UINT8(PAX_SNIFF_WIFI, last.type);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(mac, last.mac, 6);

    PaxDetectedMac batch[PaxMacTracker::MAX_MACS_PER_PACKET];
    size_t drained = tracker.drainPendingMacs(batch, PaxMacTracker::MAX_MACS_PER_PACKET);
    TEST_ASSERT_EQUAL_UINT32(1, drained);

    char msg[128];
    size_t len = PaxMacTracker::formatMacMessage(batch, drained, msg, sizeof(msg));
    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_EQUAL_STRING("Pax WiFi: 24:0A:C4:78:9A:BC (Espressif)", msg);
}

void test_record_single_ble_mac_randomized(void)
{
    // Locally administered / randomized MAC (bit 1 of byte 0 set: 0xDA & 0x02 != 0)
    const uint8_t mac[6] = {0xDA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    TEST_ASSERT_TRUE(tracker.recordDetectedMac(mac, PAX_SNIFF_BLE));
    TEST_ASSERT_EQUAL_UINT32(1, tracker.getPendingCount());

    PaxDetectedMac batch[PaxMacTracker::MAX_MACS_PER_PACKET];
    size_t drained = tracker.drainPendingMacs(batch, PaxMacTracker::MAX_MACS_PER_PACKET);
    TEST_ASSERT_EQUAL_UINT32(1, drained);

    char msg[128];
    size_t len = PaxMacTracker::formatMacMessage(batch, drained, msg, sizeof(msg));
    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_EQUAL_STRING("Pax BLE: DA:BB:CC:DD:EE:FF (Random)", msg);
}

void test_duplicate_mac_same_type_suppressed(void)
{
    const uint8_t mac[6] = {0x24, 0x0A, 0xC4, 0x44, 0x55, 0x66};
    TEST_ASSERT_TRUE(tracker.recordDetectedMac(mac, PAX_SNIFF_WIFI));
    TEST_ASSERT_EQUAL_UINT32(1, tracker.getPendingCount());

    // Second observation of the same MAC and type must be rejected as duplicate
    TEST_ASSERT_FALSE(tracker.recordDetectedMac(mac, PAX_SNIFF_WIFI));
    TEST_ASSERT_EQUAL_UINT32(1, tracker.getPendingCount());
    TEST_ASSERT_EQUAL_UINT32(1, tracker.getRecentCount());
}

void test_same_mac_different_type_allowed(void)
{
    const uint8_t mac[6] = {0x24, 0x0A, 0xC4, 0xEF, 0x01, 0x02};
    TEST_ASSERT_TRUE(tracker.recordDetectedMac(mac, PAX_SNIFF_WIFI));
    // Same MAC on BLE is a distinct device/medium and must be admitted
    TEST_ASSERT_TRUE(tracker.recordDetectedMac(mac, PAX_SNIFF_BLE));

    TEST_ASSERT_EQUAL_UINT32(2, tracker.getPendingCount());
    TEST_ASSERT_EQUAL_UINT32(2, tracker.getRecentCount());

    PaxDetectedMac batch[2];
    size_t drained = tracker.drainPendingMacs(batch, 2);
    TEST_ASSERT_EQUAL_UINT32(2, drained);
    TEST_ASSERT_EQUAL_UINT8(PAX_SNIFF_WIFI, batch[0].type);
    TEST_ASSERT_EQUAL_UINT8(PAX_SNIFF_BLE, batch[1].type);
}

void test_drain_pending_macs_batching_and_order(void)
{
    for (uint8_t i = 0; i < 6; i++) {
        const uint8_t mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, i};
        TEST_ASSERT_TRUE(tracker.recordDetectedMac(mac, PAX_SNIFF_WIFI));
    }
    TEST_ASSERT_EQUAL_UINT32(6, tracker.getPendingCount());

    // Drain up to MAX_MACS_PER_PACKET (4)
    PaxDetectedMac firstBatch[PaxMacTracker::MAX_MACS_PER_PACKET];
    size_t drained1 = tracker.drainPendingMacs(firstBatch, PaxMacTracker::MAX_MACS_PER_PACKET);
    TEST_ASSERT_EQUAL_UINT32(4, drained1);
    TEST_ASSERT_EQUAL_UINT32(2, tracker.getPendingCount());
    TEST_ASSERT_EQUAL_UINT8(0, firstBatch[0].mac[5]);
    TEST_ASSERT_EQUAL_UINT8(3, firstBatch[3].mac[5]);

    // Drain remaining 2
    PaxDetectedMac secondBatch[PaxMacTracker::MAX_MACS_PER_PACKET];
    size_t drained2 = tracker.drainPendingMacs(secondBatch, PaxMacTracker::MAX_MACS_PER_PACKET);
    TEST_ASSERT_EQUAL_UINT32(2, drained2);
    TEST_ASSERT_EQUAL_UINT32(0, tracker.getPendingCount());
    TEST_ASSERT_EQUAL_UINT8(4, secondBatch[0].mac[5]);
    TEST_ASSERT_EQUAL_UINT8(5, secondBatch[1].mac[5]);
}

void test_mac_randomization_and_oui_lookup(void)
{
    // Universal Espressif MAC
    const uint8_t espressifMac[6] = {0x24, 0x0A, 0xC4, 0x11, 0x22, 0x33};
    TEST_ASSERT_FALSE(PaxMacTracker::isRandomizedMac(espressifMac));
    TEST_ASSERT_EQUAL_STRING("Espressif", PaxMacTracker::getVendorName(espressifMac));

    // Universal Apple MAC
    const uint8_t appleMac[6] = {0x00, 0x03, 0x93, 0x12, 0x34, 0x56};
    TEST_ASSERT_FALSE(PaxMacTracker::isRandomizedMac(appleMac));
    TEST_ASSERT_EQUAL_STRING("Apple", PaxMacTracker::getVendorName(appleMac));

    // Universal Raspberry Pi MAC
    const uint8_t rpiMac[6] = {0xB8, 0x27, 0xEB, 0xAA, 0xBB, 0xCC};
    TEST_ASSERT_FALSE(PaxMacTracker::isRandomizedMac(rpiMac));
    TEST_ASSERT_EQUAL_STRING("RaspberryPi", PaxMacTracker::getVendorName(rpiMac));

    // Randomized MAC (bit 1 of byte 0 set: 0x02)
    const uint8_t randomMac1[6] = {0x02, 0x00, 0x00, 0x11, 0x22, 0x33};
    TEST_ASSERT_TRUE(PaxMacTracker::isRandomizedMac(randomMac1));
    TEST_ASSERT_EQUAL_STRING("Random", PaxMacTracker::getVendorName(randomMac1));

    // Randomized MAC (bit 1 of byte 0 set: 0xDA)
    const uint8_t randomMac2[6] = {0xDA, 0xA1, 0x19, 0x44, 0x55, 0x66};
    TEST_ASSERT_TRUE(PaxMacTracker::isRandomizedMac(randomMac2));
    TEST_ASSERT_EQUAL_STRING("Random", PaxMacTracker::getVendorName(randomMac2));

    // Universal unknown MAC (not in OUI table)
    const uint8_t unknownUniversalMac[6] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    TEST_ASSERT_FALSE(PaxMacTracker::isRandomizedMac(unknownUniversalMac));
    TEST_ASSERT_EQUAL_STRING("", PaxMacTracker::getVendorName(unknownUniversalMac));
}

void test_multi_mac_message_formatting(void)
{
    PaxDetectedMac batch[3] = {
        {{0x24, 0x0A, 0xC4, 0x01, 0x02, 0x03}, PAX_SNIFF_WIFI}, // Espressif
        {{0xDA, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}, PAX_SNIFF_BLE},  // Random
        {{0x00, 0x00, 0x01, 0x04, 0x05, 0x06}, PAX_SNIFF_WIFI}  // Unknown universal
    };

    char msg[256];
    size_t len = PaxMacTracker::formatMacMessage(batch, 3, msg, sizeof(msg));
    TEST_ASSERT_GREATER_THAN(0, len);

    const char *expected = "Pax detected:\n"
                           "WiFi: 24:0A:C4:01:02:03 (Espressif)\n"
                           "BLE: DA:0B:0C:0D:0E:0F (Random)\n"
                           "WiFi: 00:00:01:04:05:06\n";
    TEST_ASSERT_EQUAL_STRING(expected, msg);
}

void test_format_mac_message_bounds_safety(void)
{
    char buf[16];
    PaxDetectedMac single = {{0x24, 0x0A, 0xC4, 0x44, 0x55, 0x66}, PAX_SNIFF_WIFI};

    // Buffer smaller than required output must truncate safely without crashing
    size_t len = PaxMacTracker::formatMacMessage(&single, 1, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_EQUAL_UINT8('\0', buf[sizeof(buf) - 1]);

    // Zero count or null pointers should return 0 safely
    TEST_ASSERT_EQUAL_UINT32(0, PaxMacTracker::formatMacMessage(nullptr, 1, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_UINT32(0, PaxMacTracker::formatMacMessage(&single, 0, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_UINT32(0, PaxMacTracker::formatMacMessage(&single, 1, nullptr, sizeof(buf)));
    TEST_ASSERT_EQUAL_UINT32(0, PaxMacTracker::formatMacMessage(&single, 1, buf, 0));
}

void test_recent_cache_wrap_eviction(void)
{
    // Fill beyond MAX_RECENT_MACS (64) to ensure ring buffer wraps smoothly
    for (uint32_t i = 0; i < PaxMacTracker::MAX_RECENT_MACS + 10; i++) {
        const uint8_t mac[6] = {0x00, 0x00, 0x00, (uint8_t)(i >> 16), (uint8_t)(i >> 8), (uint8_t)i};
        tracker.recordDetectedMac(mac, PAX_SNIFF_WIFI);
    }
    TEST_ASSERT_EQUAL_UINT32(PaxMacTracker::MAX_RECENT_MACS, tracker.getRecentCount());
    TEST_ASSERT_EQUAL_UINT32(PaxMacTracker::MAX_PENDING_MACS, tracker.getPendingCount());
}

void test_populate_and_encode_paxcount_protobuf(void)
{
    PaxDetectedMac batch[3] = {
        {{0x24, 0x0A, 0xC4, 0x01, 0x02, 0x03}, PAX_SNIFF_WIFI}, // Espressif
        {{0xDA, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}, PAX_SNIFF_BLE},  // Random
        {{0x00, 0x00, 0x01, 0x04, 0x05, 0x06}, PAX_SNIFF_WIFI}  // Unknown universal
    };

    meshtastic_Paxcount orig = meshtastic_Paxcount_init_default;
    orig.wifi = 12;
    orig.ble = 5;
    orig.uptime = 3600;

    size_t populated = PaxMacTracker::populatePaxcountDevices(batch, 3, orig);
    TEST_ASSERT_EQUAL_UINT32(3, populated);
    TEST_ASSERT_EQUAL_UINT32(3, orig.devices_count);

    uint8_t buf[meshtastic_Paxcount_size];
    pb_ostream_t ostream = pb_ostream_from_buffer(buf, sizeof(buf));
    TEST_ASSERT_TRUE(pb_encode(&ostream, &meshtastic_Paxcount_msg, &orig));
    TEST_ASSERT_GREATER_THAN(0, ostream.bytes_written);

    meshtastic_Paxcount decoded = meshtastic_Paxcount_init_zero;
    pb_istream_t istream = pb_istream_from_buffer(buf, ostream.bytes_written);
    TEST_ASSERT_TRUE(pb_decode(&istream, &meshtastic_Paxcount_msg, &decoded));

    TEST_ASSERT_EQUAL_UINT32(12, decoded.wifi);
    TEST_ASSERT_EQUAL_UINT32(5, decoded.ble);
    TEST_ASSERT_EQUAL_UINT32(3600, decoded.uptime);
    TEST_ASSERT_EQUAL_UINT32(3, decoded.devices_count);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(batch[0].mac, decoded.devices[0].mac, 6);
    TEST_ASSERT_EQUAL_INT(meshtastic_Paxcount_SniffType_WIFI, decoded.devices[0].type);
    TEST_ASSERT_EQUAL_STRING("Espressif", decoded.devices[0].vendor);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(batch[1].mac, decoded.devices[1].mac, 6);
    TEST_ASSERT_EQUAL_INT(meshtastic_Paxcount_SniffType_BLE, decoded.devices[1].type);
    TEST_ASSERT_EQUAL_STRING("Random", decoded.devices[1].vendor);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(batch[2].mac, decoded.devices[2].mac, 6);
    TEST_ASSERT_EQUAL_INT(meshtastic_Paxcount_SniffType_WIFI, decoded.devices[2].type);
    TEST_ASSERT_EQUAL_STRING("", decoded.devices[2].vendor);
}

void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_record_single_wifi_mac_with_vendor);
    RUN_TEST(test_record_single_ble_mac_randomized);
    RUN_TEST(test_duplicate_mac_same_type_suppressed);
    RUN_TEST(test_same_mac_different_type_allowed);
    RUN_TEST(test_drain_pending_macs_batching_and_order);
    RUN_TEST(test_mac_randomization_and_oui_lookup);
    RUN_TEST(test_multi_mac_message_formatting);
    RUN_TEST(test_format_mac_message_bounds_safety);
    RUN_TEST(test_recent_cache_wrap_eviction);
    RUN_TEST(test_populate_and_encode_paxcount_protobuf);
    exit(UNITY_END());
}

void loop() {}
