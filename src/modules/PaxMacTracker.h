#pragma once

#include "meshtastic/paxcount.pb.h"
#include <cstddef>
#include <cstdint>
#include <cstring>

enum PaxSniffType : uint8_t { PAX_SNIFF_WIFI = 0, PAX_SNIFF_BLE = 1 };

struct PaxDetectedMac {
    uint8_t mac[6];
    PaxSniffType type;
};

class PaxMacTracker
{
  public:
    static constexpr size_t MAX_PENDING_MACS = 32;
    static constexpr size_t MAX_RECENT_MACS = 64;
    static constexpr size_t MAX_MACS_PER_PACKET = 4;

  private:
    PaxDetectedMac pendingMacs[MAX_PENDING_MACS] = {};
    size_t pendingCount = 0;

    PaxDetectedMac recentMacs[MAX_RECENT_MACS] = {};
    size_t recentCount = 0;
    size_t recentHead = 0;

    PaxDetectedMac lastSeenMac = {};
    bool hasLastSeenMac = false;

  public:
    PaxMacTracker() = default;

    bool recordDetectedMac(const uint8_t *mac, PaxSniffType type);
    size_t drainPendingMacs(PaxDetectedMac *outBatch, size_t maxCount);
    size_t getPendingCount() const { return pendingCount; }
    size_t getRecentCount() const { return recentCount; }
    bool getLastSeen(PaxDetectedMac &out) const;
    void clear();

    static bool isRandomizedMac(const uint8_t *mac);
    static const char *getVendorName(const uint8_t *mac);
    static size_t populatePaxcountDevices(const PaxDetectedMac *batch, size_t count, meshtastic_Paxcount &out);
    static size_t formatMacMessage(const PaxDetectedMac *batch, size_t count, char *out, size_t outLen);
};
