/*
 * OSS-Fuzz target for the IEC 61850-9-2 Sampled Values (SV) subscriber decoder.
 *
 * The SV process-bus traffic is multicast and attacker-reachable, yet the SV
 * subscriber parser (src/sampled_values/sv_subscriber.c) is not fuzzed - only
 * GOOSE is. Unlike GOOSE, the SV receiver has no public "handle a buffer" entry
 * point: a frame can only reach the parser through SVReceiver_tick(), which
 * pulls it from the Ethernet HAL via Ethernet_receivePacket().
 *
 * Rather than adding new library API, this harness provides a fuzz-only
 * Ethernet HAL implementation that delivers the fuzz input as a single frame.
 * Defining every Ethernet/EthernetHandleSet symbol that sv_subscriber.c
 * references keeps the real platform ethernet_linux.o out of the link, so the
 * existing, unmodified SVReceiver_tick() -> parseSVMessage() path is exercised.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hal_ethernet.h"
#include "sv_subscriber.h"

/* Current fuzz input, delivered once per run by the Ethernet HAL stub. */
static const uint8_t* g_frameData = NULL;
static int g_frameSize = 0;
static bool g_frameConsumed = true;

static int g_dummySocket = 0;
static int g_dummyHandleSet = 0;

/* ---- fuzz-only Ethernet HAL (replaces hal/ethernet/linux/ethernet_linux.c) ---- */

EthernetSocket
Ethernet_createSocket(const char* interfaceId, uint8_t* destAddress)
{
    (void) interfaceId;
    (void) destAddress;
    return (EthernetSocket) &g_dummySocket;
}

void
Ethernet_destroySocket(EthernetSocket ethSocket)
{
    (void) ethSocket;
}

void
Ethernet_setProtocolFilter(EthernetSocket ethSocket, uint16_t etherType)
{
    (void) ethSocket;
    (void) etherType;
}

int
Ethernet_receivePacket(EthernetSocket ethSocket, uint8_t* buffer, int bufferSize)
{
    (void) ethSocket;

    if (g_frameConsumed)
        return 0;

    int len = g_frameSize;
    if (len > bufferSize)
        len = bufferSize;

    memcpy(buffer, g_frameData, (size_t) len);
    g_frameConsumed = true;

    return len;
}

EthernetHandleSet
EthernetHandleSet_new(void)
{
    return (EthernetHandleSet) &g_dummyHandleSet;
}

void
EthernetHandleSet_addSocket(EthernetHandleSet self, const EthernetSocket sock)
{
    (void) self;
    (void) sock;
}

int
EthernetHandleSet_waitReady(EthernetHandleSet self, unsigned int timeoutMs)
{
    (void) self;
    (void) timeoutMs;
    return 1;
}

void
EthernetHandleSet_destroy(EthernetHandleSet self)
{
    (void) self;
}

static void
svUpdateListener(SVSubscriber subscriber, void* parameter, SVSubscriber_ASDU asdu)
{
    (void) subscriber;
    (void) parameter;
    (void) asdu;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0 || size > 1518)
        return 0;

    g_frameData = data;
    g_frameSize = (int) size;
    g_frameConsumed = false;

    SVReceiver receiver = SVReceiver_create();
    if (receiver == NULL)
        return 0;

    uint8_t ethAddr[6] = { 0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01 };
    SVSubscriber subscriber = SVSubscriber_create(ethAddr, 0x4000);

    if (subscriber != NULL) {
        SVSubscriber_setListener(subscriber, svUpdateListener, NULL);
        SVReceiver_addSubscriber(receiver, subscriber);
    }

    if (SVReceiver_startThreadless(receiver)) {
        SVReceiver_tick(receiver);
        SVReceiver_stopThreadless(receiver);
    }

    SVReceiver_destroy(receiver);

    return 0;
}
