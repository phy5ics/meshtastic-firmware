#include "PaxMacTracker.h"
#include <cstdio>

bool PaxMacTracker::recordDetectedMac(const uint8_t *mac, PaxSniffType type)
{
    if (!mac)
        return false;

    for (size_t i = 0; i < recentCount; i++) {
        if (recentMacs[i].type == type && memcmp(recentMacs[i].mac, mac, 6) == 0)
            return false;
    }

    memcpy(recentMacs[recentHead].mac, mac, 6);
    recentMacs[recentHead].type = type;
    recentHead = (recentHead + 1) % MAX_RECENT_MACS;
    if (recentCount < MAX_RECENT_MACS)
        recentCount++;

    if (pendingCount < MAX_PENDING_MACS) {
        memcpy(pendingMacs[pendingCount].mac, mac, 6);
        pendingMacs[pendingCount].type = type;
        pendingCount++;
    }

    memcpy(lastSeenMac.mac, mac, 6);
    lastSeenMac.type = type;
    hasLastSeenMac = true;

    return true;
}

size_t PaxMacTracker::drainPendingMacs(PaxDetectedMac *outBatch, size_t maxCount)
{
    if (!outBatch || maxCount == 0 || pendingCount == 0)
        return 0;

    size_t count = (pendingCount > maxCount) ? maxCount : pendingCount;
    for (size_t i = 0; i < count; i++) {
        outBatch[i] = pendingMacs[i];
    }
    for (size_t i = count; i < pendingCount; i++) {
        pendingMacs[i - count] = pendingMacs[i];
    }
    pendingCount -= count;

    return count;
}

bool PaxMacTracker::getLastSeen(PaxDetectedMac &out) const
{
    if (!hasLastSeenMac)
        return false;
    out = lastSeenMac;
    return true;
}

void PaxMacTracker::clear()
{
    pendingCount = 0;
    recentCount = 0;
    recentHead = 0;
    hasLastSeenMac = false;
}

size_t PaxMacTracker::formatMacMessage(const PaxDetectedMac *batch, size_t count, char *out, size_t outLen)
{
    if (!batch || count == 0 || !out || outLen == 0)
        return 0;

    if (count == 1) {
        snprintf(out, outLen, "Pax %s: %02X:%02X:%02X:%02X:%02X:%02X", (batch[0].type == PAX_SNIFF_WIFI) ? "WiFi" : "BLE",
                 batch[0].mac[0], batch[0].mac[1], batch[0].mac[2], batch[0].mac[3], batch[0].mac[4], batch[0].mac[5]);
        return strlen(out);
    }

    int offset = snprintf(out, outLen, "Pax detected:\n");
    if (offset < 0 || (size_t)offset >= outLen)
        return 0;

    for (size_t i = 0; i < count; i++) {
        int written = snprintf(out + offset, outLen - offset, "%s: %02X:%02X:%02X:%02X:%02X:%02X\n",
                               (batch[i].type == PAX_SNIFF_WIFI) ? "WiFi" : "BLE", batch[i].mac[0], batch[i].mac[1],
                               batch[i].mac[2], batch[i].mac[3], batch[i].mac[4], batch[i].mac[5]);
        if (written < 0 || (size_t)(offset + written) >= outLen)
            break;
        offset += written;
    }

    return offset;
}
