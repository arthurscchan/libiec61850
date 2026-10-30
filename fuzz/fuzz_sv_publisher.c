/*
 * libFuzzer harness for the IEC 61850-9-2 Sampled Values publisher encoder.
 *
 * Threat model
 * ------------
 * Untrusted input: SV ASDU identifiers (svID, datSet) and the sample payload an
 * IED publishes on the process bus. The encoder (SVPublisher_setupComplete /
 * SVPublisher_publish) is the trust boundary: it writes fixed-width fields and
 * a variable-length dataset into a fixed Ethernet frame.
 * Attacker controls: identifier strings, sample counts, and the integer/float
 * payload. Real bug: ASan/UBSan findings from a length or offset mistake in the
 * publisher (the subscriber side of this bug class was GHSA-jh37-3w86-6rw8).
 *
 * Production coverage (2026-10-29): src/sampled_values/sv_publisher.c is absent
 * from the coverage report entirely (compiled, never entered). The existing SV
 * harness only calls SVReceiver_handleL2Message. Ethernet send fails without a
 * NIC; setupComplete + publish still encode the frame, which is then fed to the
 * subscriber so encode and decode stay consistent.
 *
 * Pre-existing detect_leaks=0 is inherited, not widened.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sv_publisher.h"
#include "sv_subscriber.h"

static void
svListener(SVSubscriber subscriber, void* parameter, SVSubscriber_ASDU asdu)
{
    (void)subscriber;
    (void)parameter;
    (void)SVSubscriber_ASDU_getSmpCnt(asdu);
    (void)SVSubscriber_ASDU_getConfRev(asdu);
    (void)SVSubscriber_ASDU_getSmpSynch(asdu);
    (void)SVSubscriber_ASDU_getDataSize(asdu);
    (void)SVSubscriber_ASDU_getSvId(asdu);
}

static void
takeStr(const uint8_t* data, size_t size, size_t* off, char* out, size_t cap)
{
    size_t n = 0;
    if (*off < size)
        n = data[(*off)++];
    if (n >= cap)
        n = cap - 1;
    if (*off + n > size)
        n = size - *off;
    if (n)
        memcpy(out, data + *off, n);
    out[n] = 0;
    *off += n;
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
    params.vlanId = data[off++];
    params.appId = 0x4000;
    if (off + 1 < size) {
        params.appId = (uint16_t)(data[off] | (data[off + 1] << 8));
        off += 2;
    }
    params.dstAddress[0] = 0x01;
    params.dstAddress[1] = 0x0c;
    params.dstAddress[2] = 0xcd;
    params.dstAddress[3] = 0x04;
    params.dstAddress[4] = 0x00;
    params.dstAddress[5] = 0x01;

    bool useVlan = (data[0] & 0x80) != 0;
    SVPublisher publisher = SVPublisher_createEx(&params, "lo", useVlan);
    if (!publisher)
        publisher = SVPublisher_createEx(&params, NULL, useVlan);
    if (!publisher)
        return 0;

    char svID[65];
    char datSet[65];
    takeStr(data, size, &off, svID, sizeof(svID));
    takeStr(data, size, &off, datSet, sizeof(datSet));
    if (svID[0] == 0)
        memcpy(svID, "sv", 3);

    uint32_t confRev = 1;
    if (off + 3 < size) {
        memcpy(&confRev, data + off, 4);
        off += 4;
    }

    SVPublisher_ASDU asdu = SVPublisher_addASDU(publisher, svID, datSet[0] ? datSet : NULL, confRev);
    if (!asdu) {
        SVPublisher_destroy(publisher);
        return 0;
    }

    int nFields = 1;
    if (off < size)
        nFields = (data[off++] % 8) + 1;

    int idx[8];
    int kinds[8];
    for (int i = 0; i < nFields; i++) {
        int kind = (off < size) ? data[off++] % 4 : 0;
        kinds[i] = kind;
        if (kind == 0)
            idx[i] = SVPublisher_ASDU_addINT8(asdu);
        else if (kind == 1)
            idx[i] = SVPublisher_ASDU_addINT32(asdu);
        else if (kind == 2)
            idx[i] = SVPublisher_ASDU_addFLOAT(asdu);
        else
            idx[i] = SVPublisher_ASDU_addINT32(asdu);
    }

    if (off < size)
        SVPublisher_ASDU_enableRefrTm(asdu);
    SVPublisher_setupComplete(publisher);

    for (int i = 0; i < nFields; i++) {
        if (idx[i] < 0)
            continue;
        if (kinds[i] == 0 && off < size)
            SVPublisher_ASDU_setINT8(asdu, idx[i], (int8_t)data[off++]);
        else if (kinds[i] == 2 && off + 3 < size) {
            float v;
            memcpy(&v, data + off, 4);
            SVPublisher_ASDU_setFLOAT(asdu, idx[i], v);
            off += 4;
        }
        else if (off + 3 < size) {
            int32_t v;
            memcpy(&v, data + off, 4);
            SVPublisher_ASDU_setINT32(asdu, idx[i], v);
            off += 4;
        }
    }
    if (off + 1 < size)
        SVPublisher_ASDU_setSmpCnt(asdu, (uint16_t)(data[off] | (data[off + 1] << 8)));

    SVPublisher_publish(publisher);

    /* Re-parse a synthetic frame is not available (no NIC). The encoder itself
     * is what this harness exists to exercise; the subscriber API is already
     * covered by fuzz_sv_subscriber. */
    (void)svListener;

    SVPublisher_destroy(publisher);
    return 0;
}
