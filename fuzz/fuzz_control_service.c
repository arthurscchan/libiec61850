/*
 * libFuzzer harness for the IEC 61850 control service (client + server).
 *
 * Threat model
 * ------------
 * Untrusted input: the control operations a malicious or compromised client
 * performs against an IED server - select / selectWithValue / operate /
 * cancel, the control model in force (status-only, direct-normal, SBO-normal,
 * direct-enhanced, SBO-enhanced), test mode, interlock and synchro check
 * flags, ctlNum, origin (orCat + orIdent), the control value itself, and the
 * verdicts the server-side application handlers return. The trust boundaries
 * are the client-side ControlObjectClient request builders
 * (src/iec61850/client/client_control.c) and the server-side control state
 * machine (src/iec61850/server/mms_mapping/control.c), reached over a real
 * MMS association on loopback.
 * Attacker controls: every parameter above, byte for byte.
 * Real bug: any ASan/UBSan finding in the select/operate/cancel state
 * machine, time-activated operate, SBO timeout handling, or LastApplError /
 * command-termination reporting (control.c: 4/1887 lines, 1/71 functions in
 * the 2026-11-10 production report; client_control.c: 0/875 lines).
 *
 * Shape: persistent loopback session. The server (IedServer_start - its own
 * thread runs the periodic control task that executes the state machine) and
 * the client association are created once; each iteration decodes 12-byte
 * operation records and performs them through the public client API, so the
 * per-iteration cost is a few MMS writes over an established connection.
 * A per-iteration connect/accept loop was tried for the file service and was
 * structurally too slow to explore (28 runs in 122 s); this shape avoids it.
 * No dictionary: the op-stream encoding has no mutation-resistant gate -
 * every byte mutates into a still-valid operation, so dictionary work has
 * zero incremental worth here.
 *
 * Pre-existing detect_leaks=0 for the whole harness set is inherited, not
 * widened. No product code is modified; only public APIs are used.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hal_thread.h"
#include "hal_time.h"
#include "iec61850_model.h"
#include "iec61850_client.h"
#include "iec61850_cdc.h"
#include "iec61850_server.h"
#include "mms_value.h"

#define CONTROL_PORT 8102
#define OP_RECORD_SIZE 12
#define MAX_OPS 64
#define NUM_TARGETS 3

static const char* const kObjectRefs[NUM_TARGETS] = {
    "fzLD0/GGIO1.SPC1", /* controllable single point, boolean ctlVal     */
    "fzLD0/GGIO1.SPC2", /* SPC, time-activated capable (operTm)         */
    "fzLD0/GGIO1.INC1"  /* controllable integer status, int32 ctlVal    */
};

/* Verdict knobs read by the server-side handlers (server worker thread). */
static volatile int8_t g_checkVerdict;  /* CheckHandlerResult selection    */
static volatile int8_t g_operVerdict;   /* ControlHandlerResult selection  */
static volatile int8_t g_waitVerdict;   /* waitForExecution selection      */

static IedServer g_server;
static IedConnection g_con;
static ControlObjectClient g_co[NUM_TARGETS];
static bool g_clientReady;

static const CheckHandlerResult kCheckVerdicts[] = {
    CONTROL_ACCEPTED,
    CONTROL_ACCEPTED,
    CONTROL_WAITING_FOR_SELECT,
    CONTROL_HARDWARE_FAULT,
    CONTROL_TEMPORARILY_UNAVAILABLE,
    CONTROL_OBJECT_ACCESS_DENIED,
    CONTROL_OBJECT_UNDEFINED,
    CONTROL_VALUE_INVALID
};

static ControlHandlerResult
verdictFromSelector(int8_t selector)
{
    switch (selector % 3) {
    case 0:
        return CONTROL_RESULT_OK;
    case 1:
        return CONTROL_RESULT_FAILED;
    default:
        return CONTROL_RESULT_WAITING;
    }
}

static CheckHandlerResult
checkHandler(ControlAction action, void* parameter, MmsValue* ctlVal, bool test,
        bool interlockCheck)
{
    (void)action;
    (void)parameter;
    (void)ctlVal;
    (void)test;
    (void)interlockCheck;
    return kCheckVerdicts[(uint8_t)g_checkVerdict % 8];
}

static ControlHandlerResult
operateHandler(ControlAction action, void* parameter, MmsValue* ctlVal, bool test)
{
    (void)action;
    (void)parameter;
    (void)ctlVal;
    (void)test;
    return verdictFromSelector(g_operVerdict);
}

static ControlHandlerResult
waitHandler(ControlAction action, void* parameter, MmsValue* ctlVal, bool test,
        bool synchroCheck)
{
    (void)action;
    (void)parameter;
    (void)ctlVal;
    (void)test;
    (void)synchroCheck;
    return verdictFromSelector(g_waitVerdict);
}

static void
selectStateChangedHandler(ControlAction action, void* parameter, bool isSelected,
        SelectStateChangedReason reason);

static void
releaseClient(void)
{
    int i;

    for (i = 0; i < NUM_TARGETS; i++) {
        if (g_co[i]) {
            ControlObjectClient_destroy(g_co[i]);
            g_co[i] = NULL;
        }
    }

    if (g_con) {
        IedConnection_destroy(g_con);
        g_con = NULL;
    }

    g_clientReady = false;
}

static void
connectClient(void)
{
    IedClientError err;
    MmsConnection mms;
    int attempt;

    releaseClient();

    g_con = IedConnection_create();
    if (g_con == NULL)
        return;

    mms = IedConnection_getMmsConnection(g_con);
    MmsConnection_setConnectTimeout(mms, 1000);
    MmsConnection_setRequestTimeout(mms, 2000);

    /* The server acceptor may need a moment after IedServer_start. */
    for (attempt = 0; attempt < 20; attempt++) {
        IedConnection_connect(g_con, &err, "127.0.0.1", CONTROL_PORT);
        if (err == IED_ERROR_OK)
            break;
        Thread_sleep(50);
    }

    if (err != IED_ERROR_OK)
        return;

    for (attempt = 0; attempt < NUM_TARGETS; attempt++) {
        g_co[attempt] = ControlObjectClient_create(kObjectRefs[attempt], g_con);
        if (g_co[attempt] == NULL)
            return;
    }

    g_clientReady = true;
}

static int
initOnce(void)
{
    IedModel* model;
    LogicalDevice* ld;
    LogicalNode* ln;
    DataObject* spc1;
    DataObject* spc2;
    DataObject* inc1;
    uint32_t ctlOpts;

    ctlOpts = CDC_CTL_OPTION_ORIGIN | CDC_CTL_OPTION_CTL_NUM |
            CDC_CTL_OPTION_SBO_TIMEOUT | CDC_CTL_OPTION_SBO_CLASS |
            CDC_CTL_OPTION_ST_SELD | CDC_CTL_OPTION_OP_RCVD |
            CDC_CTL_OPTION_OP_OK | CDC_CTL_OPTION_T_OP_OK;

    model = IedModel_create("fz");
    if (model == NULL)
        return 1;

    ld = LogicalDevice_create("LD0", model);
    ln = LogicalNode_create("GGIO1", ld);

    spc1 = CDC_SPC_create("SPC1", (ModelNode*)ln, 0,
            CDC_CTL_MODEL_DIRECT_ENHANCED | CDC_CTL_MODEL_HAS_CANCEL | ctlOpts);

    spc2 = CDC_SPC_create("SPC2", (ModelNode*)ln, 0,
            CDC_CTL_MODEL_SBO_NORMAL | CDC_CTL_MODEL_HAS_CANCEL |
            CDC_CTL_MODEL_IS_TIME_ACTIVATED | ctlOpts);

    inc1 = CDC_INC_create("INC1", (ModelNode*)ln, 0,
            CDC_CTL_MODEL_DIRECT_NORMAL | CDC_CTL_MODEL_HAS_CANCEL | ctlOpts);

    if (spc1 == NULL || spc2 == NULL || inc1 == NULL)
        return 1;

    g_server = IedServer_create(model);
    if (g_server == NULL)
        return 1;

    IedServer_setControlHandler(g_server, spc1, operateHandler, NULL);
    IedServer_setControlHandler(g_server, spc2, operateHandler, NULL);
    IedServer_setControlHandler(g_server, inc1, operateHandler, NULL);

    IedServer_setPerformCheckHandler(g_server, spc1, checkHandler, NULL);
    IedServer_setPerformCheckHandler(g_server, spc2, checkHandler, NULL);
    IedServer_setPerformCheckHandler(g_server, inc1, checkHandler, NULL);

    IedServer_setWaitForExecutionHandler(g_server, spc1, waitHandler, NULL);
    IedServer_setWaitForExecutionHandler(g_server, spc2, waitHandler, NULL);
    IedServer_setWaitForExecutionHandler(g_server, inc1, waitHandler, NULL);

    IedServer_setSelectStateChangedHandler(g_server, spc1,
            selectStateChangedHandler, NULL);
    IedServer_setSelectStateChangedHandler(g_server, spc2,
            selectStateChangedHandler, NULL);
    IedServer_setSelectStateChangedHandler(g_server, inc1,
            selectStateChangedHandler, NULL);

    IedServer_start(g_server, CONTROL_PORT);

    connectClient();
    return 0;
}

static void
selectStateChangedHandler(ControlAction action, void* parameter, bool isSelected,
        SelectStateChangedReason reason)
{
    (void)action;
    (void)parameter;
    (void)isSelected;
    (void)reason;
}

static MmsValue*
makeCtlVal(ControlObjectClient co, uint32_t payload)
{
    MmsType type = ControlObjectClient_getCtlValType(co);

    switch (type) {
    case MMS_BOOLEAN:
        return MmsValue_newBoolean((payload & 1) != 0);

    case MMS_UNSIGNED:
        return MmsValue_newUnsignedFromUint32(payload);

    case MMS_INTEGER:
    default:
        return MmsValue_newIntegerFromInt32((int32_t)payload);
    }
}

static uint32_t
readPay32(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
            ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    size_t off;
    bool touched[NUM_TARGETS] = {false, false, false};
    int i;

    if (g_server == NULL) {
        if (initOnce() != 0)
            return 0;
    }

    if (g_clientReady == false) {
        connectClient();
        if (g_clientReady == false)
            return 0;
    }

    off = 0;

    while (off + OP_RECORD_SIZE <= size && off < OP_RECORD_SIZE * MAX_OPS) {
        uint8_t opcode = (uint8_t)(data[off] % 8);
        uint8_t flags = data[off + 1];
        uint8_t ctlModel = data[off + 2] % 5;
        int target = (int)(data[off + 3] % NUM_TARGETS);
        uint8_t ctlNum = data[off + 4];
        uint8_t orCat = (uint8_t)(data[off + 5] % 8);
        uint8_t operVerdictSel = data[off + 7] & 3;
        uint8_t waitVerdictSel = (data[off + 7] >> 2) & 3;
        uint32_t payload = readPay32(data + off + 8);
        char orIdent[8];
        ControlObjectClient co = g_co[target];

        off += OP_RECORD_SIZE;

        if (co == NULL)
            continue;

        g_checkVerdict = (int8_t)(flags >> 4);
        g_operVerdict = (int8_t)operVerdictSel;
        g_waitVerdict = (int8_t)waitVerdictSel;

        snprintf(orIdent, sizeof(orIdent), "%06x", payload & 0xffffff);

        switch (opcode) {

        case 0:
            /* switch the server-side control model of the target */
            ControlObjectClient_changeServerControlModel(co,
                    (ControlModel)ctlModel);
            break;

        case 1:
            if (ControlObjectClient_select(co) == true)
                touched[target] = true;
            break;

        case 2:
            if (ControlObjectClient_selectWithValue(co,
                    makeCtlVal(co, payload)) == true)
                touched[target] = true;
            break;

        case 3:
            ControlObjectClient_setCtlNum(co, ctlNum);
            ControlObjectClient_setOrigin(co, orIdent, (int)orCat);
            /* operTm at most 1 s in the future, so the server response always
             * arrives inside the 2 s request timeout on loopback */
            ControlObjectClient_operate(co, makeCtlVal(co, payload),
                    Hal_getTimeInMs() + (uint64_t)((int32_t)(payload % 1500) - 500));
            touched[target] = true;
            break;

        case 4:
            ControlObjectClient_cancel(co);
            touched[target] = false;
            break;

        case 5:
            ControlObjectClient_setTestMode(co, (flags & 1) != 0);
            ControlObjectClient_setInterlockCheck(co, (flags & 2) != 0);
            ControlObjectClient_setSynchroCheck(co, (flags & 4) != 0);
            ControlObjectClient_useConstantT(co, (flags & 8) != 0);
            break;

        case 6:
            (void)ControlObjectClient_getLastApplError(co);
            break;

        default:
            /* client-side view only, no server write */
            ControlObjectClient_setControlModel(co, (ControlModel)ctlModel);
            break;
        }

        /* the association may have been dropped by a request timeout */
        if (IedConnection_getState(g_con) != IED_STATE_CONNECTED) {
            connectClient();
            if (g_clientReady == false)
                return 0;
        }
    }

    /* leave no selection behind, so iterations stay mostly independent */
    for (i = 0; i < NUM_TARGETS; i++) {
        if (touched[i] && g_co[i])
            ControlObjectClient_cancel(g_co[i]);
    }

    return 0;
}

