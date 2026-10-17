// Unit tests for PaxMacTracker in src/modules/PaxMacTracker.h and src/modules/PaxMacTracker.cpp.
//
// The Paxcounter module sniffs surrounding Wi-Fi probe requests and Bluetooth Low Energy advertisements.
// Instead of merely aggregating these into device counts, PaxMacTracker identifies unique MAC addresses,
// deduplicates them against recently seen devices, stages them into an outbound queue, and formats them
// into text message broadcasts for the mesh network.
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

#include "Arduino.h"
#include "TestUtil.h"
#include "modules/PaxMacTracker.h"
#include <cstring>
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

void test_record_single_wifi_mac(void)
{
    const uint8_t mac[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
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
    TEST_ASSERT_EQUAL_STRING("Pax WiFi: 12:34:56:78:9A:BC", msg);
}

void test_record_single_ble_mac(void)
{
    const uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    TEST_ASSERT_TRUE(tracker.recordDetectedMac(mac, PAX_SNIFF_BLE));
    TEST_ASSERT_EQUAL_UINT32(1, tracker.getPendingCount());

    PaxDetectedMac batch[PaxMacTracker::MAX_MACS_PER_PACKET];
    size_t drained = tracker.drainPendingMacs(batch, PaxMacTracker::MAX_MACS_PER_PACKET);
    TEST_ASSERT_EQUAL_UINT32(1, drained);

    char msg[128];
    size_t len = PaxMacTracker::formatMacMessage(batch, drained, msg, sizeof(msg));
    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_EQUAL_STRING("Pax BLE: AA:BB:CC:DD:EE:FF", msg);
}

void test_duplicate_mac_same_type_suppressed(void)
{
    const uint8_t mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    TEST_ASSERT_TRUE(tracker.recordDetectedMac(mac, PAX_SNIFF_WIFI));
    TEST_ASSERT_EQUAL_UINT32(1, tracker.getPendingCount());

    // Second observation of the same MAC and type must be rejected as duplicate
    TEST_ASSERT_FALSE(tracker.recordDetectedMac(mac, PAX_SNIFF_WIFI));
    TEST_ASSERT_EQUAL_UINT32(1, tracker.getPendingCount());
    TEST_ASSERT_EQUAL_UINT32(1, tracker.getRecentCount());
}

void test_same_mac_different_type_allowed(void)
{
    const uint8_t mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
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
    for (uint8_t i = 0; i < 8; i++) {
        const uint8_t mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, i};
        TEST_ASSERT_TRUE(tracker.recordDetectedMac(mac, PAX_SNIFF_WIFI));
    }
    TEST_ASSERT_EQUAL_UINT32(8, tracker.getPendingCount());

    // Drain up to MAX_MACS_PER_PACKET (6)
    PaxDetectedMac firstBatch[PaxMacTracker::MAX_MACS_PER_PACKET];
    size_t drained1 = tracker.drainPendingMacs(firstBatch, PaxMacTracker::MAX_MACS_PER_PACKET);
    TEST_ASSERT_EQUAL_UINT32(6, drained1);
    TEST_ASSERT_EQUAL_UINT32(2, tracker.getPendingCount());
    TEST_ASSERT_EQUAL_UINT8(0, firstBatch[0].mac[5]);
    TEST_ASSERT_EQUAL_UINT8(5, firstBatch[5].mac[5]);

    // Drain remaining 2
    PaxDetectedMac secondBatch[PaxMacTracker::MAX_MACS_PER_PACKET];
    size_t drained2 = tracker.drainPendingMacs(secondBatch, PaxMacTracker::MAX_MACS_PER_PACKET);
    TEST_ASSERT_EQUAL_UINT32(2, drained2);
    TEST_ASSERT_EQUAL_UINT32(0, tracker.getPendingCount());
    TEST_ASSERT_EQUAL_UINT8(6, secondBatch[0].mac[5]);
    TEST_ASSERT_EQUAL_UINT8(7, secondBatch[1].mac[5]);
}

void test_multi_mac_message_formatting(void)
{
    PaxDetectedMac batch[2] = {{{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, PAX_SNIFF_WIFI},
                               {{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}, PAX_SNIFF_BLE}};

    char msg[256];
    size_t len = PaxMacTracker::formatMacMessage(batch, 2, msg, sizeof(msg));
    TEST_ASSERT_GREATER_THAN(0, len);

    const char *expected = "Pax detected:\n"
                           "WiFi: 01:02:03:04:05:06\n"
                           "BLE: 0A:0B:0C:0D:0E:0F\n";
    TEST_ASSERT_EQUAL_STRING(expected, msg);
}

void test_format_mac_message_bounds_safety(void)
{
    char buf[16];
    PaxDetectedMac single = {{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, PAX_SNIFF_WIFI};

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

void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_record_single_wifi_mac);
    RUN_TEST(test_record_single_ble_mac);
    RUN_TEST(test_duplicate_mac_same_type_suppressed);
    RUN_TEST(test_same_mac_different_type_allowed);
    RUN_TEST(test_drain_pending_macs_batching_and_order);
    RUN_TEST(test_multi_mac_message_formatting);
    RUN_TEST(test_format_mac_message_bounds_safety);
    RUN_TEST(test_recent_cache_wrap_eviction);
    exit(UNITY_END());
}

void loop() {}
