/*
 * libFuzzer harness for the IEC 61850 GOOSE publisher encoder.
 *
 * Threat model
 * ------------
 * Untrusted input: GOOSE dataset values and control-block strings (goCbRef,
 * datSet, goID) that a publisher encodes onto the process bus. A compromised
 * application or a crafted configuration controls those values. The encoder is
 * the trust boundary: it BER-encodes arbitrary MmsValue trees into a fixed-size
 * Ethernet frame (createGoosePayload / MmsValue_encodeMmsData).
 * Attacker controls: dataset member types and lengths, and the identifier strings.
 * Real bug: ASan/UBSan findings from a length miscalculation or an overflow of
 * the GOOSE frame buffer.
 *
 * Production coverage (2026-10-29): src/goose/goose_publisher.c is 0% functions
 * (261 uncovered lines). The existing GOOSE harness only drives the subscriber.
 * Ethernet_createSocket fails in the OSS-Fuzz container (no NIC);
 * GoosePublisher_publish still runs the encoder before the send. The encoded
 * frame is handed to GooseReceiver_handleMessage so encode and decode agree.
 *
 * Pre-existing integration sets detect_leaks=0 for every harness; inherited
 * unchanged, not widened.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "goose_publisher.h"
#include "goose_receiver.h"
#include "goose_subscriber.h"
#include "mms_value.h"
#include "linked_list.h"

static void
gooseListener(GooseSubscriber subscriber, void* parameter)
{
    (void)subscriber;
    (void)parameter;
}

static char*
takeString(const uint8_t* data, size_t size, size_t* off, size_t maxLen)
{
    if (*off >= size)
        return NULL;
    size_t n = data[(*off)++];
    if (n > maxLen)
        n = maxLen;
    if (*off + n > size)
        n = size - *off;
    char* s = (char*)malloc(n + 1);
    if (!s)
        return NULL;
    if (n)
        memcpy(s, data + *off, n);
    s[n] = 0;
    *off += n;
    return s;
}

static MmsValue*
takeValue(const uint8_t* data, size_t size, size_t* off, int depth)
{
    if (*off >= size || depth > 3)
        return MmsValue_newBoolean(false);

    uint8_t tag = data[(*off)++];
    switch (tag % 7) {
    case 0:
        return MmsValue_newBoolean((*off < size) && (data[*off] & 1));
    case 1: {
        int32_t v = 0;
        if (*off + 4 <= size) {
            memcpy(&v, data + *off, 4);
            *off += 4;
        }
        return MmsValue_newIntegerFromInt32(v);
    }
    case 2: {
        float v = 0;
        if (*off + 4 <= size) {
            memcpy(&v, data + *off, 4);
            *off += 4;
        }
        return MmsValue_newFloat(v);
    }
    case 3: {
        char* s = takeString(data, size, off, 64);
        MmsValue* val = MmsValue_newVisibleString(s ? s : "");
        free(s);
        return val;
    }
    case 4: {
        size_t n = (*off < size) ? data[(*off)++] : 0;
        if (n > 32)
            n = 32;
        if (*off + n > size)
            n = size - *off;
        MmsValue* val = MmsValue_newOctetString((int)n, (int)n);
        if (val && n)
            MmsValue_setOctetString(val, (uint8_t*)(data + *off), (int)n);
        *off += n;
        return val;
    }
    case 5: {
        int count = (*off < size) ? (data[(*off)++] % 4) + 1 : 1;
        MmsValue* arr = MmsValue_createEmptyArray(count);
        if (!arr)
            return MmsValue_newBoolean(false);
        for (int i = 0; i < count; i++)
            MmsValue_setElement(arr, i, takeValue(data, size, off, depth + 1));
        return arr;
    }
    default: {
        int bitSize = (*off < size) ? (data[(*off)++] % 32) + 1 : 8;
        MmsValue* bits = MmsValue_newBitString(bitSize);
        return bits ? bits : MmsValue_newBoolean(false);
    }
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 4)
        return 0;

    size_t off = 0;
    CommParameters params;
    memset(&params, 0, sizeof(params));
    params.vlanPriority = data[off++] & 0x7;
    if (off + 1 < size) {
        params.vlanId = (uint16_t)(data[off] | (data[off + 1] << 8));
        off += 2;
    }
    if (off + 1 < size) {
        params.appId = (uint16_t)(data[off] | (data[off + 1] << 8));
        off += 2;
    }
    params.dstAddress[0] = 0x01;
    params.dstAddress[1] = 0x0c;
    params.dstAddress[2] = 0xcd;
    params.dstAddress[3] = 0x01;
    params.dstAddress[4] = 0x00;
    params.dstAddress[5] = 0x01;

    bool useVlan = (data[0] & 0x80) != 0;
    GoosePublisher publisher = GoosePublisher_createEx(&params, "lo", useVlan);
    if (!publisher)
        publisher = GoosePublisher_createEx(&params, NULL, useVlan);
    if (!publisher)
        return 0;

    char* goCbRef = takeString(data, size, &off, 80);
    char* dataSetRef = takeString(data, size, &off, 80);
    char* goID = takeString(data, size, &off, 80);

    if (goCbRef)
        GoosePublisher_setGoCbRef(publisher, goCbRef);
    if (dataSetRef)
        GoosePublisher_setDataSetRef(publisher, dataSetRef);
    if (goID)
        GoosePublisher_setGoID(publisher, goID);

    if (off < size)
        GoosePublisher_setTimeAllowedToLive(publisher, data[off++]);
    if (off + 3 < size) {
        uint32_t confRev;
        memcpy(&confRev, data + off, 4);
        GoosePublisher_setConfRev(publisher, confRev);
        off += 4;
    }
    if (off < size) {
        GoosePublisher_setSimulation(publisher, (data[off] & 1) != 0);
        GoosePublisher_setNeedsCommission(publisher, (data[off] & 2) != 0);
        off++;
    }
    if (off + 3 < size) {
        uint32_t stNum;
        memcpy(&stNum, data + off, 4);
        GoosePublisher_setStNum(publisher, stNum);
        off += 4;
    }

    int members = 1;
    if (off < size)
        members = (data[off++] % 6) + 1;

    LinkedList dataSet = LinkedList_create();
    if (dataSet) {
        for (int i = 0; i < members; i++) {
            MmsValue* value = takeValue(data, size, &off, 0);
            if (value)
                LinkedList_add(dataSet, value);
        }

        uint8_t frame[2048];
        int32_t frameLen = 0;
        GoosePublisher_publishAndDump(publisher, dataSet, (char*)frame, &frameLen, (int32_t)sizeof(frame));

        if (frameLen > 0 && frameLen <= (int32_t)sizeof(frame)) {
            GooseReceiver receiver = GooseReceiver_create();
            if (receiver) {
                GooseSubscriber subscriber = GooseSubscriber_create(goCbRef ? goCbRef : "", NULL);
                if (subscriber) {
                    GooseSubscriber_setListener(subscriber, gooseListener, NULL);
                    GooseReceiver_addSubscriber(receiver, subscriber);
                }
                GooseReceiver_startThreadless(receiver);
                GooseReceiver_handleMessage(receiver, frame, frameLen);
                GooseReceiver_stop(receiver);
                GooseReceiver_destroy(receiver);
            }
        }

        LinkedList_destroyDeep(dataSet, (LinkedListValueDeleteFunction)MmsValue_delete);
    }

    GoosePublisher_destroy(publisher);
    free(goCbRef);
    free(dataSetRef);
    free(goID);
    return 0;
}

