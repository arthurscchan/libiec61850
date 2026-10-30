/*
 * libFuzzer harness for the IEC 61850 model configuration-file parser.
 *
 * Threat model
 * ------------
 * Untrusted input: a text configuration file (the .cfg format produced by the
 * library's configuration-file tool, or any file an operator loads into an IED
 * server). Attackers who can supply or tamper with that file control the whole
 * buffer.
 * Trust boundary: ConfigFileParser_createModelFromConfigFile(), the public API
 * that turns the file into an IedModel. The parser is a hand-written recursive
 * descent over MODEL/LD/LN/DO/DA/DS/RC/GC/LC/SG/LOG/SMVC/PA lines with sscanf
 * into fixed 130-byte name buffers and a 1024-byte line buffer.
 * Attacker controls: the entire file contents.
 * Real bug: any ASan/UBSan finding while parsing a crafted configuration file
 * (overflow of the fixed name buffers, integer issues in array-element counts,
 * use-after-free while tearing down a partially built model).
 *
 * Production coverage (2026-10-29): src/iec61850/server/model/config_file_parser.c
 * is compiled into the library and has 0/0 function coverage. No existing
 * harness calls ConfigFileParser_*.
 *
 * The input is written to a temp file because the public API takes a FileHandle,
 * not a memory buffer. The file is removed before return.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "iec61850_server.h"
#include "iec61850_config_file_parser.h"
#include "hal_filesystem.h"

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    char path[] = "/tmp/iec61850-cfg-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        return 0;

    size_t off = 0;
    while (off < size) {
        ssize_t n = write(fd, data + off, size - off);
        if (n <= 0)
            break;
        off += (size_t)n;
    }
    close(fd);

    FileHandle handle = FileSystem_openFile(path, false);
    if (handle != NULL) {
        IedModel* model = ConfigFileParser_createModelFromConfigFile(handle);
        FileSystem_closeFile(handle);
        if (model != NULL)
            IedModel_destroy(model);
    }

    unlink(path);
    return 0;
}
