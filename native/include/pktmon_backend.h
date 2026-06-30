#pragma once

#include <stdint.h>

#ifdef _WIN32
#define PKTMON_EXPORT extern "C" __declspec(dllexport)
#else
#define PKTMON_EXPORT extern "C"
#endif

enum PktmonStatus : int32_t {
    PKTMON_OK = 0,
    PKTMON_E_WINDOWS_ONLY = -1,
    PKTMON_E_LOAD_DLL = -2,
    PKTMON_E_MISSING_EXPORT = -3,
    PKTMON_E_INVALID_ARGUMENT = -4,
    PKTMON_E_NOT_STARTED = -5,
    PKTMON_E_ABI_UNMAPPED = -6,
    PKTMON_E_PROCESS = -7,
    PKTMON_E_TIMEOUT = -8,
    PKTMON_E_INTERNAL = -100,
};

enum PktmonProtocol : uint32_t {
    PKTMON_PROTO_UNKNOWN = 0,
    PKTMON_PROTO_TCP = 6,
    PKTMON_PROTO_UDP = 17,
};

struct PktmonProbeInfo {
    uint32_t struct_size;
    uint32_t export_count;
    uint32_t missing_count;
    uint32_t capture_ready;
    uint32_t reserved;
};

struct PktmonPacket {
    uint32_t struct_size;
    double timestamp_unix;
    uint32_t protocol;
    uint16_t source_port;
    uint16_t destination_port;
    char source_address[64];
    char destination_address[64];
    const uint8_t* payload;
    uint32_t payload_size;
};

struct PktmonCaptureConfig {
    uint32_t struct_size;
    uint32_t queue_capacity;
    uint16_t buffer_size_multiplier;
    uint16_t truncation_size;
    uint8_t include_empty_payloads;
    uint8_t reserved[5];
};

using PktmonHandle = void*;

PKTMON_EXPORT int32_t PktmonVersion();
PKTMON_EXPORT int32_t PktmonProbe(PktmonProbeInfo* info);
PKTMON_EXPORT uint32_t PktmonGetExportReport(char* buffer, uint32_t buffer_size);
PKTMON_EXPORT PktmonHandle PktmonCreate();
PKTMON_EXPORT void PktmonDestroy(PktmonHandle handle);
PKTMON_EXPORT int32_t PktmonStart(PktmonHandle handle, const char* filter);
PKTMON_EXPORT int32_t PktmonStartConfig(
    PktmonHandle handle,
    const char* filter,
    const PktmonCaptureConfig* config);
PKTMON_EXPORT int32_t PktmonRead(PktmonHandle handle, PktmonPacket* packet, uint32_t timeout_ms);
PKTMON_EXPORT int32_t PktmonReadBatch(
    PktmonHandle handle,
    PktmonPacket* packets,
    uint32_t packet_count,
    uint32_t timeout_ms,
    uint32_t* packets_read);
PKTMON_EXPORT void PktmonStop(PktmonHandle handle);
PKTMON_EXPORT uint32_t PktmonLastError(PktmonHandle handle, char* buffer, uint32_t buffer_size);

