#include "configuration.h"
#if defined(ARCH_ESP32) && !MESHTASTIC_EXCLUDE_PAXCOUNTER
#include "Default.h"
#include "MeshService.h"
#include "PaxcounterModule.h"
#include "airtime.h"
#include "graphics/ScreenFonts.h"
#include "graphics/SharedUIDisplay.h"
#include "graphics/images.h"
#include <esp_event.h>
#include <freertos/timers.h>

typedef enum { MAC_SNIFF_WIFI, MAC_SNIFF_BLE, MAC_SNIFF_BLE_ENS } snifftype_t;

extern "C" {
int __real__Z7mac_addPh11snifftype_t(uint8_t *paddr, snifftype_t sniff_type);
int __wrap__Z7mac_addPh11snifftype_t(uint8_t *paddr, snifftype_t sniff_type);
}

int __wrap__Z7mac_addPh11snifftype_t(uint8_t *paddr, snifftype_t sniff_type)
{
    int added = __real__Z7mac_addPh11snifftype_t(paddr, sniff_type);
    if (paxcounterModule && paxcounterModule->isActive()) {
        PaxSniffType type = (sniff_type == MAC_SNIFF_WIFI) ? PAX_SNIFF_WIFI : PAX_SNIFF_BLE;
        paxcounterModule->recordDetectedMac(paddr, type);
    }
    return added;
}

// Arduino WiFi has a wifiscan.h too, so declare the libpax scanner hooks here.
void set_wifi_channels(uint16_t channels_map);
void wifi_sniffer_init(uint16_t wifi_channel_switch_interval);
void switchWifiChannel(TimerHandle_t xTimer);
extern TimerHandle_t WifiChanTimer;

static void startWifiChannelTimer(uint16_t wifi_channel_switch_interval)
{
    if (wifi_channel_switch_interval == 0) {
        return;
    }

    WifiChanTimer =
        xTimerCreate("WifiChannelTimer", pdMS_TO_TICKS(wifi_channel_switch_interval * 10), pdTRUE, (void *)0, switchWifiChannel);
    if (!WifiChanTimer) {
        LOG_WARN("Paxcounter can't create WiFi channel switch timer");
        return;
    }
    xTimerStart(WifiChanTimer, 0);
}

static void ensureDefaultEventLoop()
{
    esp_err_t result = esp_event_loop_create_default();
    if (result != ESP_OK && result != ESP_ERR_INVALID_STATE) {
        LOG_WARN("Paxcounter can't create ESP event loop: %d", result);
    }
}

PaxcounterModule *paxcounterModule;

/**
 * Callback function for libpax.
 * We only clear our sent flag here, since this function is called from another thread, so we
 * cannot send to the mesh directly.
 */
void PaxcounterModule::handlePaxCounterReportRequest()
{
    // The libpax library already updated our data structure, just before invoking this callback.
    LOG_INFO("PaxcounterModule: libpax reported new data: wifi=%d; ble=%d; uptime=%lu",
             paxcounterModule->count_from_libpax.wifi_count, paxcounterModule->count_from_libpax.ble_count, millis() / 1000);
    paxcounterModule->reportedDataSent = false;
    paxcounterModule->setIntervalFromNow(0);
}

PaxcounterModule::PaxcounterModule()
    : concurrency::OSThread("Paxcounter"),
      ProtobufModule("paxcounter", meshtastic_PortNum_PAXCOUNTER_APP, &meshtastic_Paxcount_msg)
{
}

/**
 * Send the Pax information to the mesh if we got new data from libpax.
 * This is called periodically from our runOnce() method and will actually send the data to the mesh
 * if libpax updated it since the last transmission through the callback.
 * @param dest - destination node (usually NODENUM_BROADCAST)
 * @return false if sending is unnecessary, true if information was sent
 */
bool PaxcounterModule::sendInfo(NodeNum dest)
{
    if (paxcounterModule->reportedDataSent)
        return false;

    LOG_INFO("PaxcounterModule: send pax info wifi=%d; ble=%d; uptime=%lu", count_from_libpax.wifi_count,
             count_from_libpax.ble_count, millis() / 1000);

    meshtastic_Paxcount pl = meshtastic_Paxcount_init_default;
    pl.wifi = count_from_libpax.wifi_count;
    pl.ble = count_from_libpax.ble_count;
    pl.uptime = millis() / 1000;

    meshtastic_MeshPacket *p = allocDataProtobuf(pl);
    if (!p)
        return false;
    p->to = dest;
    p->decoded.want_response = false;
    p->priority = meshtastic_MeshPacket_Priority_BACKGROUND;

    service->sendToMesh(p, RX_SRC_LOCAL, true);

    paxcounterModule->reportedDataSent = true;

    return true;
}

bool PaxcounterModule::handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_Paxcount *p)
{
    return false; // Let others look at this message also if they want. We don't do anything with received packets.
}

void PaxcounterModule::recordDetectedMac(const uint8_t *mac, PaxSniffType type)
{
    portENTER_CRITICAL(&macMux);
    macTracker.recordDetectedMac(mac, type);
    portEXIT_CRITICAL(&macMux);
}

bool PaxcounterModule::sendDetectedMacs(NodeNum dest)
{
    PaxDetectedMac batch[PaxMacTracker::MAX_MACS_PER_PACKET];
    size_t count = 0;

    portENTER_CRITICAL(&macMux);
    count = macTracker.drainPendingMacs(batch, PaxMacTracker::MAX_MACS_PER_PACKET);
    portEXIT_CRITICAL(&macMux);

    if (count == 0)
        return false;

    char message[meshtastic_Constants_DATA_PAYLOAD_LEN];
    PaxMacTracker::formatMacMessage(batch, count, message, sizeof(message));

    meshtastic_MeshPacket *p = router->allocForSending();
    if (!p)
        return false;

    p->to = dest;
    p->decoded.want_response = false;
    p->priority = meshtastic_MeshPacket_Priority_BACKGROUND;
    p->decoded.portnum = meshtastic_PortNum_TEXT_MESSAGE_APP;
    p->decoded.payload.size = strlen(message);
    memcpy(p->decoded.payload.bytes, message, p->decoded.payload.size);

    LOG_INFO("PaxcounterModule: sending MAC broadcast (%d devices): %s", (int)count, message);
    service->sendToMesh(p, RX_SRC_LOCAL, true);

    return true;
}

meshtastic_MeshPacket *PaxcounterModule::allocReply()
{
    meshtastic_Paxcount pl = meshtastic_Paxcount_init_default;
    pl.wifi = count_from_libpax.wifi_count;
    pl.ble = count_from_libpax.ble_count;
    pl.uptime = millis() / 1000;
    return allocDataProtobuf(pl);
}

int32_t PaxcounterModule::runOnce()
{
    if (isActive()) {
        if (firstTime) {
            firstTime = false;
            LOG_DEBUG("Paxcounter starting up with interval of %d seconds",
                      Default::getConfiguredOrDefault(moduleConfig.paxcounter.paxcounter_update_interval,
                                                      default_telemetry_broadcast_interval_secs));
            struct libpax_config_t configuration;
            libpax_default_config(&configuration);

            configuration.blecounter = 1;
            configuration.blescantime = 0; // infinite
            configuration.wificounter = 1;
            configuration.LIBPAX_WIFI_CHANNEL_map = LIBPAX_WIFI_CHANNEL_ALL;
            configuration.LIBPAX_WIFI_CHANNEL_switch_interval = 50;
            configuration.wifi_rssi_threshold = Default::getConfiguredOrDefault(moduleConfig.paxcounter.wifi_threshold, -80);
            configuration.ble_rssi_threshold = Default::getConfiguredOrDefault(moduleConfig.paxcounter.ble_threshold, -80);
            libpax_update_config(&configuration);

            // internal processing initialization
            libpax_counter_init(handlePaxCounterReportRequest, &count_from_libpax,
                                Default::getConfiguredOrDefault(moduleConfig.paxcounter.paxcounter_update_interval,
                                                                default_telemetry_broadcast_interval_secs),
                                0);
            // libpax sets the WiFi country in counter_start(), so start channel rotation after that.
            ensureDefaultEventLoop();
            set_wifi_channels(configuration.LIBPAX_WIFI_CHANNEL_map);
            wifi_sniffer_init(0);
            libpax_counter_start();
            startWifiChannelTimer(configuration.LIBPAX_WIFI_CHANNEL_switch_interval);
        } else {
            sendInfo(NODENUM_BROADCAST);
            while (airTime->isTxAllowedAirUtil() && sendDetectedMacs(NODENUM_BROADCAST)) {
            }
        }
        return Default::getConfiguredOrDefaultMsScaled(moduleConfig.paxcounter.paxcounter_update_interval,
                                                       default_telemetry_broadcast_interval_secs, numOnlineNodes);
    } else {
        return disable();
    }
}

#if HAS_SCREEN

#include "graphics/ScreenFonts.h"
#include "graphics/SharedUIDisplay.h"

void PaxcounterModule::drawFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y)
{
    display->clear();
    display->setTextAlignment(TEXT_ALIGN_LEFT);
    display->setFont(FONT_SMALL);
    int line = 1;

    // === Set Title
    const char *titleStr = "Pax";

    // === Header ===
    graphics::drawCommonHeader(display, x, y, titleStr);

    char buffer[64];
    display->setTextAlignment(TEXT_ALIGN_LEFT);
    display->setFont(FONT_SMALL);

    libpax_counter_count(&count_from_libpax);

    PaxDetectedMac last;
    bool hasLast = false;
    portENTER_CRITICAL(&macMux);
    hasLast = macTracker.getLastSeen(last);
    portEXIT_CRITICAL(&macMux);

    display->setTextAlignment(TEXT_ALIGN_CENTER);
    display->setFont(FONT_SMALL);
    if (hasLast) {
        display->drawStringf(display->getWidth() / 2 + x, graphics::getTextPositions(display)[line++], buffer,
                             "WiFi: %d BLE: %d\n%s %02X:%02X:%02X:%02X\nUptime: %lus", count_from_libpax.wifi_count,
                             count_from_libpax.ble_count, (last.type == PAX_SNIFF_WIFI) ? "WiFi" : "BLE", last.mac[2],
                             last.mac[3], last.mac[4], last.mac[5], (unsigned long)(millis() / 1000));
    } else {
        display->drawStringf(display->getWidth() / 2 + x, graphics::getTextPositions(display)[line++], buffer,
                             "WiFi: %d\nBLE: %d\nUptime: %ds", count_from_libpax.wifi_count, count_from_libpax.ble_count,
                             millis() / 1000);
    }
    graphics::drawCommonFooter(display, x, y);
}
#endif // HAS_SCREEN

#endif
