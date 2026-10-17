#include "PaxMacTracker.h"
#include <cstdio>

struct OuiVendorEntry {
    uint32_t oui;
    const char *vendor;
};

static const OuiVendorEntry OUI_TABLE[] = {
    {0x00000C, "Cisco"},       {0x0000F0, "Samsung"},     {0x000142, "Cisco"},       {0x000143, "Cisco"},
    {0x00014A, "Sony"},        {0x000163, "Cisco"},       {0x000164, "Cisco"},       {0x0001C7, "Cisco"},
    {0x0001C9, "Cisco"},       {0x000216, "Cisco"},       {0x000217, "Cisco"},       {0x00024A, "Cisco"},
    {0x00024B, "Cisco"},       {0x00027D, "Cisco"},       {0x00027E, "Cisco"},       {0x0002B3, "Intel"},
    {0x0002B9, "Cisco"},       {0x0002BA, "Cisco"},       {0x0002FC, "Cisco"},       {0x0002FD, "Cisco"},
    {0x000331, "Cisco"},       {0x000332, "Cisco"},       {0x000347, "Intel"},       {0x00036B, "Cisco"},
    {0x00036C, "Cisco"},       {0x000393, "Apple"},       {0x0003A0, "Cisco"},       {0x00041F, "Sony"},
    {0x000423, "Intel"},       {0x000456, "Motorola"},    {0x000502, "Apple"},       {0x0005C9, "LG"},
    {0x0007AB, "Samsung"},     {0x0007E9, "Intel"},       {0x00085C, "TI"},          {0x000A27, "Apple"},
    {0x000A28, "Motorola"},    {0x000A75, "Sony"},        {0x000A95, "Apple"},       {0x000C43, "Motorola"},
    {0x000C76, "Intel"},       {0x000D0B, "Sony"},        {0x000D18, "Sony"},        {0x000D3A, "Microsoft"},
    {0x000D93, "Apple"},       {0x000DAE, "Samsung"},     {0x000E07, "Sony"},        {0x000E0C, "Motorola"},
    {0x000E35, "Intel"},       {0x000E6A, "Motorola"},    {0x000F43, "Sony"},        {0x0010FA, "Apple"},
    {0x001111, "Intel"},       {0x001124, "Apple"},       {0x0011AE, "Motorola"},    {0x001247, "Samsung"},
    {0x001249, "TI"},          {0x00125A, "Microsoft"},   {0x00128A, "Motorola"},    {0x001302, "Intel"},
    {0x0013A9, "Sony"},        {0x0013E8, "Intel"},       {0x001451, "Apple"},       {0x00149A, "Motorola"},
    {0x001500, "Intel"},       {0x00155D, "Microsoft"},   {0x001599, "Samsung"},     {0x00159B, "Sony"},
    {0x0015A8, "Motorola"},    {0x001632, "Samsung"},     {0x001644, "Sony"},        {0x00166F, "Intel"},
    {0x0016CB, "Apple"},       {0x0016EA, "Intel"},       {0x0017C9, "Samsung"},     {0x0017E9, "TI"},
    {0x0017EE, "Motorola"},    {0x0017F2, "Apple"},       {0x0017FA, "Microsoft"},   {0x001831, "TI"},
    {0x001882, "Huawei"},      {0x001889, "Motorola"},    {0x00192D, "Motorola"},    {0x0019C1, "LG"},
    {0x0019C5, "Sony"},        {0x0019D1, "Intel"},       {0x0019E3, "Apple"},       {0x001A11, "Google"},
    {0x001A66, "Motorola"},    {0x001A80, "Sony"},        {0x001A8A, "Samsung"},     {0x001B63, "Apple"},
    {0x001B77, "Intel"},       {0x001C11, "Motorola"},    {0x001C42, "Apple"},       {0x001C62, "Intel"},
    {0x001D0D, "Sony"},        {0x001D25, "Samsung"},     {0x001D43, "Intel"},       {0x001D4F, "Apple"},
    {0x001D60, "Microsoft"},   {0x001D6B, "Motorola"},    {0x001E10, "Huawei"},      {0x001E45, "Sony"},
    {0x001E52, "Apple"},       {0x001E64, "Intel"},       {0x001E65, "Intel"},       {0x001E75, "LG"},
    {0x001E8C, "Motorola"},    {0x001EC0, "Nordic"},      {0x001F3B, "Intel"},       {0x001F5B, "Apple"},
    {0x001F6B, "LG"},          {0x001FF3, "Apple"},       {0x002041, "Motorola"},    {0x002119, "Samsung"},
    {0x00215C, "Intel"},       {0x00216A, "Intel"},       {0x00217C, "Motorola"},    {0x00219E, "Sony"},
    {0x0021E9, "Apple"},       {0x002241, "Apple"},       {0x002243, "Motorola"},    {0x002248, "Microsoft"},
    {0x0022FB, "Intel"},       {0x002312, "Apple"},       {0x002314, "Intel"},       {0x002332, "Apple"},
    {0x00234D, "Sony"},        {0x002368, "Motorola"},    {0x00236C, "Apple"},       {0x0023A7, "TI"},
    {0x0023D7, "Samsung"},     {0x0023DF, "Apple"},       {0x002436, "Apple"},       {0x002437, "Motorola"},
    {0x002483, "LG"},          {0x00248D, "Sony"},        {0x002490, "Samsung"},     {0x002492, "Motorola"},
    {0x0024D7, "Intel"},       {0x002500, "Apple"},       {0x00254B, "Apple"},       {0x002568, "Huawei"},
    {0x00259E, "Huawei"},      {0x0025AE, "Microsoft"},   {0x0025BC, "Apple"},       {0x002604, "Sony"},
    {0x002608, "Apple"},       {0x002637, "Samsung"},     {0x00264A, "Apple"},       {0x0026B0, "Apple"},
    {0x0026B3, "Motorola"},    {0x0026BB, "Apple"},       {0x0026C6, "Intel"},       {0x0026C7, "Intel"},
    {0x0026E2, "LG"},          {0x003318, "Nordic"},      {0x003714, "Nordic"},      {0x00464B, "Huawei"},
    {0x0050F2, "Microsoft"},   {0x006124, "Nordic"},      {0x006B8E, "Nordic"},      {0x007886, "Nordic"},
    {0x0083B6, "Nordic"},      {0x00EC0A, "Xiaomi"},      {0x00FC8B, "Amazon"},      {0x04A316, "TI"},
    {0x04C06F, "Huawei"},      {0x04CF4B, "Xiaomi"},      {0x081196, "Intel"},       {0x0819A6, "Huawei"},
    {0x087A4C, "Huawei"},      {0x08FC88, "Samsung"},     {0x0C37DC, "Huawei"},      {0x0C47C9, "Amazon"},
    {0x101B54, "Huawei"},      {0x104780, "Huawei"},      {0x10C61F, "Huawei"},      {0x10D561, "Tuya"},
    {0x10F96F, "LG"},          {0x143004, "Motorola"},    {0x14A51A, "Huawei"},      {0x14F42A, "Samsung"},
    {0x14F65A, "Xiaomi"},      {0x180852, "TI"},          {0x185936, "Xiaomi"},      {0x18742E, "Amazon"},
    {0x18FE34, "Espressif"},   {0x1C5CF2, "Google"},      {0x2008ED, "Huawei"},      {0x240AC4, "Espressif"},
    {0x244B03, "Samsung"},     {0x2462AB, "Espressif"},   {0x24B2DE, "Espressif"},   {0x24DC67, "Espressif"},
    {0x24DF6A, "Huawei"},      {0x281878, "Microsoft"},   {0x286C07, "Xiaomi"},      {0x286ED4, "Huawei"},
    {0x28CDC1, "RaspberryPi"}, {0x28CFE9, "Apple"},       {0x2C3AE8, "Espressif"},   {0x30AEA4, "Espressif"},
    {0x3413E8, "Intel"},       {0x346B46, "Huawei"},      {0x3480B3, "Xiaomi"},      {0x34C059, "Samsung"},
    {0x34D270, "Amazon"},      {0x34FC9F, "LG"},          {0x384C90, "Huawei"},      {0x38F73D, "Amazon"},
    {0x3C438E, "Motorola"},    {0x3C5AB4, "Google"},      {0x3C6105, "Espressif"},   {0x3C71BF, "Espressif"},
    {0x3CD0F8, "Apple"},       {0x404D8E, "Huawei"},      {0x4083DE, "Motorola"},    {0x40B4CD, "Amazon"},
    {0x40D32D, "Apple"},       {0x40EC99, "TI"},          {0x44650D, "Amazon"},      {0x44B7D0, "TI"},
    {0x4844F7, "Samsung"},     {0x4846FB, "Huawei"},      {0x4851B7, "Intel"},       {0x485519, "Espressif"},
    {0x486276, "Huawei"},      {0x4C7525, "Espressif"},   {0x4CABFF, "Huawei"},      {0x508569, "Samsung"},
    {0x508A06, "Tuya"},        {0x50C7BF, "Motorola"},    {0x50DC01, "Amazon"},      {0x545A46, "Espressif"},
    {0x546009, "Google"},      {0x546C0E, "TI"},          {0x548998, "Huawei"},      {0x584498, "Xiaomi"},
    {0x58A2B5, "LG"},          {0x5C0A5B, "Samsung"},     {0x5CD998, "Huawei"},      {0x600308, "Apple"},
    {0x6045BD, "Microsoft"},   {0x6055F9, "Espressif"},   {0x608334, "Samsung"},     {0x60BEB5, "Motorola"},
    {0x60DE44, "Huawei"},      {0x640980, "Xiaomi"},      {0x6805CA, "Intel"},       {0x68545A, "Amazon"},
    {0x68B6B3, "Espressif"},   {0x68C90B, "TI"},          {0x70039F, "Espressif"},   {0x703A51, "Google"},
    {0x7054F5, "Huawei"},      {0x70DEE2, "Apple"},       {0x7451BA, "Xiaomi"},      {0x747548, "Amazon"},
    {0x74A722, "LG"},          {0x782184, "Espressif"},   {0x784B87, "Samsung"},     {0x78D752, "Huawei"},
    {0x78E36D, "Tuya"},        {0x7C1DDA, "Xiaomi"},      {0x7C9EBD, "Espressif"},   {0x8030DC, "TI"},
    {0x8086F2, "Intel"},       {0x80B686, "Huawei"},      {0x840D8E, "Espressif"},   {0x842519, "Samsung"},
    {0x847BFB, "Motorola"},    {0x84CCA8, "Espressif"},   {0x84D6D0, "Amazon"},      {0x84F703, "Tuya"},
    {0x8853D4, "Huawei"},      {0x88665A, "Apple"},       {0x888603, "Huawei"},      {0x8C1645, "Intel"},
    {0x8C34FD, "Huawei"},      {0x8C4B14, "Espressif"},   {0x8CBEBE, "Xiaomi"},      {0x90477C, "Huawei"},
    {0x9463D1, "Samsung"},     {0x94659C, "OnePlus"},     {0x94B97E, "Espressif"},   {0x94EB2C, "Google"},
    {0x98F170, "Motorola"},    {0x98F4AB, "Espressif"},   {0x98FA9B, "Xiaomi"},      {0x9C04EB, "Apple"},
    {0x9C28F7, "OnePlus"},     {0x9CFBB8, "Huawei"},      {0xA020A6, "Espressif"},   {0xA0E6F8, "TI"},
    {0xA402B9, "Intel"},       {0xA47733, "Google"},      {0xA4C361, "Apple"},       {0xA4CF12, "Espressif"},
    {0xA816B2, "LG"},          {0xAC220B, "OnePlus"},     {0xAC63BE, "Amazon"},      {0xAC67B2, "Espressif"},
    {0xAC853D, "Huawei"},      {0xACBC32, "Apple"},       {0xACF1DF, "Xiaomi"},      {0xB05B67, "Huawei"},
    {0xB07994, "Motorola"},    {0xB09122, "TI"},          {0xB4055D, "Huawei"},      {0xB47C9C, "Amazon"},
    {0xB4E62D, "Espressif"},   {0xB827EB, "RaspberryPi"}, {0xB8E856, "Apple"},       {0xBC8556, "Samsung"},
    {0xBC926B, "Apple"},       {0xBCDD68, "Espressif"},   {0xC04E30, "Espressif"},   {0xC09727, "TI"},
    {0xC0EEFB, "OnePlus"},     {0xC40BCB, "Xiaomi"},      {0xC4366C, "LG"},          {0xC44F33, "Espressif"},
    {0xC47D4F, "Motorola"},    {0xC82A14, "Apple"},       {0xC82E18, "Espressif"},   {0xC85B76, "Intel"},
    {0xC8D15E, "Huawei"},      {0xCC50E3, "Espressif"},   {0xCC9E00, "Amazon"},      {0xD03972, "TI"},
    {0xD059E4, "Samsung"},     {0xD481D7, "Nordic"},      {0xD4970B, "Xiaomi"},      {0xD4D4DA, "Espressif"},
    {0xD81E5E, "Tuya"},        {0xD83ADD, "RaspberryPi"}, {0xD8490B, "Huawei"},      {0xD86C63, "Google"},
    {0xD8A01D, "Espressif"},   {0xDC2632, "RaspberryPi"}, {0xDC2B61, "Apple"},       {0xDC5360, "Microsoft"},
    {0xDC5475, "Espressif"},   {0xDC7144, "Motorola"},    {0xE01954, "Huawei"},      {0xE04F43, "TI"},
    {0xE09806, "Espressif"},   {0xE435C8, "Huawei"},      {0xE45F01, "RaspberryPi"}, {0xE47CF9, "Samsung"},
    {0xE85B5B, "LG"},          {0xE868E7, "Espressif"},   {0xEC233D, "Huawei"},      {0xEC64C9, "Espressif"},
    {0xF01898, "Apple"},       {0xF0EC80, "TI"},          {0xF409D8, "Samsung"},     {0xF412FA, "Espressif"},
    {0xF4559C, "Huawei"},      {0xF4CE36, "Nordic"},      {0xF4F5DB, "Google"},      {0xF8A45F, "Xiaomi"},
    {0xF8CF45, "Motorola"},    {0xFC65DE, "Amazon"},
};

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

bool PaxMacTracker::isRandomizedMac(const uint8_t *mac)
{
    if (!mac)
        return false;
    return (mac[0] & 0x02) != 0;
}

const char *PaxMacTracker::getVendorName(const uint8_t *mac)
{
    if (!mac)
        return "";

    if (isRandomizedMac(mac))
        return "Random";

    uint32_t targetOui = ((uint32_t)mac[0] << 16) | ((uint32_t)mac[1] << 8) | (uint32_t)mac[2];

    int left = 0;
    int right = (int)(sizeof(OUI_TABLE) / sizeof(OUI_TABLE[0])) - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (OUI_TABLE[mid].oui == targetOui) {
            return OUI_TABLE[mid].vendor;
        }
        if (OUI_TABLE[mid].oui < targetOui) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    return "";
}

size_t PaxMacTracker::formatMacMessage(const PaxDetectedMac *batch, size_t count, char *out, size_t outLen)
{
    if (!batch || count == 0 || !out || outLen == 0)
        return 0;

    if (count == 1) {
        const char *vendor = getVendorName(batch[0].mac);
        if (vendor && vendor[0] != '\0') {
            snprintf(out, outLen, "Pax %s: %02X:%02X:%02X:%02X:%02X:%02X (%s)",
                     (batch[0].type == PAX_SNIFF_WIFI) ? "WiFi" : "BLE", batch[0].mac[0], batch[0].mac[1], batch[0].mac[2],
                     batch[0].mac[3], batch[0].mac[4], batch[0].mac[5], vendor);
        } else {
            snprintf(out, outLen, "Pax %s: %02X:%02X:%02X:%02X:%02X:%02X", (batch[0].type == PAX_SNIFF_WIFI) ? "WiFi" : "BLE",
                     batch[0].mac[0], batch[0].mac[1], batch[0].mac[2], batch[0].mac[3], batch[0].mac[4], batch[0].mac[5]);
        }
        return strlen(out);
    }

    int offset = snprintf(out, outLen, "Pax detected:\n");
    if (offset < 0 || (size_t)offset >= outLen)
        return 0;

    for (size_t i = 0; i < count; i++) {
        const char *vendor = getVendorName(batch[i].mac);
        int written = 0;
        if (vendor && vendor[0] != '\0') {
            written = snprintf(out + offset, outLen - offset, "%s: %02X:%02X:%02X:%02X:%02X:%02X (%s)\n",
                               (batch[i].type == PAX_SNIFF_WIFI) ? "WiFi" : "BLE", batch[i].mac[0], batch[i].mac[1],
                               batch[i].mac[2], batch[i].mac[3], batch[i].mac[4], batch[i].mac[5], vendor);
        } else {
            written = snprintf(out + offset, outLen - offset, "%s: %02X:%02X:%02X:%02X:%02X:%02X\n",
                               (batch[i].type == PAX_SNIFF_WIFI) ? "WiFi" : "BLE", batch[i].mac[0], batch[i].mac[1],
                               batch[i].mac[2], batch[i].mac[3], batch[i].mac[4], batch[i].mac[5]);
        }
        if (written < 0 || (size_t)(offset + written) >= outLen)
            break;
        offset += written;
    }

    return offset;
}
