#include "../include/pktmon_backend.h"
#include "../include/pktmon_api.h"

#include <windows.h>

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <new>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr int32_t kVersion = 3;

constexpr std::array<const char*, 9> kPktmonExports = {
    "PacketMonitorAddCaptureConstraint",
    "PacketMonitorAttachOutputToSession",
    "PacketMonitorCloseRealtimeStream",
    "PacketMonitorCloseSessionHandle",
    "PacketMonitorCreateLiveSession",
    "PacketMonitorCreateRealtimeStream",
    "PacketMonitorInitialize",
    "PacketMonitorSetSessionActive",
    "PacketMonitorUninitialize",
};

struct ParsedPacket {
    double timestamp_unix = 0.0;
    uint32_t protocol = PKTMON_PROTO_UNKNOWN;
    uint16_t source_port = 0;
    uint16_t destination_port = 0;
    std::string source_address;
    std::string destination_address;
    std::vector<uint8_t> payload;
};

struct CaptureState {
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<ParsedPacket> queue;
    std::vector<uint8_t> read_payload;
    std::atomic<bool> stopping = false;
    bool started = false;
    HMODULE pktmon_api = nullptr;
    PACKETMONITOR_HANDLE api_handle = nullptr;
    PACKETMONITOR_SESSION session_handle = nullptr;
    PACKETMONITOR_REALTIME_STREAM stream_handle = nullptr;
    std::string last_error;
};

using FnPacketMonitorInitialize =
    HRESULT(WINAPI*)(uint32_t, void*, PACKETMONITOR_HANDLE*);
using FnPacketMonitorUninitialize = HRESULT(WINAPI*)(PACKETMONITOR_HANDLE);
using FnPacketMonitorCreateLiveSession =
    HRESULT(WINAPI*)(PACKETMONITOR_HANDLE, PCWSTR, PACKETMONITOR_SESSION*);
using FnPacketMonitorCloseSessionHandle = HRESULT(WINAPI*)(PACKETMONITOR_SESSION);
using FnPacketMonitorCreateRealtimeStream = HRESULT(WINAPI*)(
    PACKETMONITOR_HANDLE,
    const PACKETMONITOR_REALTIME_STREAM_CONFIGURATION*,
    PACKETMONITOR_REALTIME_STREAM*);
using FnPacketMonitorCloseRealtimeStream = HRESULT(WINAPI*)(PACKETMONITOR_REALTIME_STREAM);
using FnPacketMonitorAttachOutputToSession =
    HRESULT(WINAPI*)(PACKETMONITOR_SESSION, void*);
using FnPacketMonitorSetSessionActive = HRESULT(WINAPI*)(PACKETMONITOR_SESSION, BOOLEAN);
using FnPacketMonitorAddCaptureConstraint =
    HRESULT(WINAPI*)(PACKETMONITOR_SESSION, const PACKETMONITOR_PROTOCOL_CONSTRAINT*);

struct DirectApi {
    FnPacketMonitorInitialize initialize = nullptr;
    FnPacketMonitorUninitialize uninitialize = nullptr;
    FnPacketMonitorCreateLiveSession create_session = nullptr;
    FnPacketMonitorCloseSessionHandle close_session = nullptr;
    FnPacketMonitorCreateRealtimeStream create_stream = nullptr;
    FnPacketMonitorCloseRealtimeStream close_stream = nullptr;
    FnPacketMonitorAttachOutputToSession attach_output = nullptr;
    FnPacketMonitorSetSessionActive set_active = nullptr;
    FnPacketMonitorAddCaptureConstraint add_capture_constraint = nullptr;
};

static_assert(
    sizeof(PACKETMONITOR_REALTIME_STREAM_CONFIGURATION) == 0x20,
    "PktMonApi stream configuration ABI changed");
static_assert(
    sizeof(PACKETMONITOR_STREAM_DATA_DESCRIPTOR) == 0x20,
    "PktMonApi stream data descriptor ABI changed");

struct ExportProbe {
    HMODULE module = nullptr;
    std::vector<std::string> missing;
};

void set_error(CaptureState* state, const std::string& message) {
    if (state == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(state->mutex);
    state->last_error = message;
}

std::string hresult_message(const char* step, long hr) {
    std::ostringstream out;
    out << step << " failed: HRESULT=0x" << std::hex << static_cast<uint32_t>(hr);
    return out.str();
}

bool failed_hr(long hr) {
    return hr < 0;
}

uint64_t unix_time_now_filetime() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER value;
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

double unix_time_now() {
    constexpr uint64_t kUnixEpochFileTime = 116444736000000000ULL;
    const uint64_t now = unix_time_now_filetime();
    return static_cast<double>(now - kUnixEpochFileTime) / 10000000.0;
}

double unix_time_from_system_time(int64_t system_time) {
    constexpr int64_t kUnixEpochFileTime = 116444736000000000LL;
    if (system_time <= kUnixEpochFileTime) {
        return unix_time_now();
    }
    return static_cast<double>(system_time - kUnixEpochFileTime) / 10000000.0;
}

ExportProbe probe_exports() {
    ExportProbe probe;
    probe.module = LoadLibraryW(L"PktMonApi.dll");
    if (probe.module == nullptr) {
        probe.missing.assign(kPktmonExports.begin(), kPktmonExports.end());
        return probe;
    }

    for (const char* name : kPktmonExports) {
        if (GetProcAddress(probe.module, name) == nullptr) {
            probe.missing.emplace_back(name);
        }
    }
    return probe;
}

std::string export_report() {
    ExportProbe probe = probe_exports();
    std::ostringstream out;
    const bool capture_ready = probe.module != nullptr && probe.missing.empty();
    out << "{";
    out << "\"dll_loaded\":" << (probe.module != nullptr ? "true" : "false") << ",";
    out << "\"capture_ready\":" << (capture_ready ? "true" : "false") << ",";
    out << "\"backend\":\"PktMonApi.dll direct realtime stream\",";
    out << "\"exports\":[";
    bool first = true;
    for (const char* name : kPktmonExports) {
        if (!first) {
            out << ",";
        }
        first = false;
        const bool present =
            probe.module != nullptr && GetProcAddress(probe.module, name) != nullptr;
        out << "{\"name\":\"" << name << "\",\"present\":"
            << (present ? "true" : "false") << "}";
    }
    out << "],";
    out << "\"note\":\"PktMonApi.dll realtime stream is the only capture backend\"";
    out << "}";
    if (probe.module != nullptr) {
        FreeLibrary(probe.module);
    }
    return out.str();
}

uint32_t copy_text(const std::string& text, char* buffer, uint32_t buffer_size) {
    const uint32_t needed = static_cast<uint32_t>(text.size() + 1);
    if (buffer == nullptr || buffer_size == 0) {
        return needed;
    }
    const uint32_t count = needed <= buffer_size ? needed : buffer_size;
    memcpy(buffer, text.c_str(), count - 1);
    buffer[count - 1] = '\0';
    return needed;
}

bool contains_case_insensitive(const std::string& text, const std::string& needle) {
    auto lower = [](char c) -> char {
        if (c >= 'A' && c <= 'Z') {
            return static_cast<char>(c + ('a' - 'A'));
        }
        return c;
    };
    if (needle.empty()) {
        return true;
    }
    for (size_t i = 0; i + needle.size() <= text.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (lower(text[i + j]) != lower(needle[j])) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return true;
        }
    }
    return false;
}

int extract_port_after(const std::string& filter, const std::string& marker) {
    size_t pos = filter.find(marker);
    if (pos == std::string::npos) {
        return 0;
    }
    pos += marker.size();
    while (pos < filter.size() && filter[pos] == ' ') {
        ++pos;
    }
    int value = 0;
    while (pos < filter.size() && filter[pos] >= '0' && filter[pos] <= '9') {
        value = value * 10 + (filter[pos] - '0');
        ++pos;
    }
    return value;
}

std::string ascii_lower(std::string text) {
    for (char& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c + ('a' - 'A'));
        }
    }
    return text;
}

void set_constraint_name(PACKETMONITOR_PROTOCOL_CONSTRAINT* constraint, const wchar_t* name) {
    if (constraint == nullptr || name == nullptr) {
        return;
    }
    wcsncpy_s(constraint->Name, PACKETMONITOR_MAX_NAME_LENGTH, name, _TRUNCATE);
}

HRESULT add_protocol_constraint(
    const DirectApi& api,
    PACKETMONITOR_SESSION session,
    const wchar_t* name,
    uint8_t protocol,
    uint16_t source_port,
    uint16_t destination_port) {
    PACKETMONITOR_PROTOCOL_CONSTRAINT constraint{};
    set_constraint_name(&constraint, name);
    constraint.IsPresent.TransportProtocol = 1;
    constraint.TransportProtocol = protocol;
    if (source_port > 0) {
        constraint.IsPresent.Port1 = 1;
        constraint.Port1 = source_port;
    }
    if (destination_port > 0) {
        constraint.IsPresent.Port2 = 1;
        constraint.Port2 = destination_port;
    }
    return api.add_capture_constraint(session, &constraint);
}

bool configure_session_constraints(
    const DirectApi& api,
    PACKETMONITOR_SESSION session,
    const std::string& filter,
    std::string* error) {
    if (api.add_capture_constraint == nullptr || session == nullptr) {
        if (error != nullptr) {
            *error = "PacketMonitorAddCaptureConstraint is not available";
        }
        return false;
    }

    const std::string lower = ascii_lower(filter);
    auto add_or_error = [&](const wchar_t* name,
                            uint8_t protocol,
                            uint16_t source_port,
                            uint16_t destination_port) -> bool {
        HRESULT hr = add_protocol_constraint(
            api,
            session,
            name,
            protocol,
            source_port,
            destination_port);
        if (failed_hr(hr)) {
            if (error != nullptr) {
                *error = hresult_message("PacketMonitorAddCaptureConstraint", hr);
            }
            return false;
        }
        return true;
    };

    if (contains_case_insensitive(lower, "tcp")) {
        int port = extract_port_after(lower, "tcp port");
        if (port <= 0) {
            port = extract_port_after(lower, "port");
        }
        if (port > 65535) {
            if (error != nullptr) {
                *error = "tcp port is outside the valid range";
            }
            return false;
        }
        if (port > 0) {
            if (!add_or_error(
                    L"PktmonInterfaceTcpSource",
                    PKTMON_PROTO_TCP,
                    static_cast<uint16_t>(port),
                    0) ||
                !add_or_error(
                    L"PktmonInterfaceTcpDestination",
                    PKTMON_PROTO_TCP,
                    0,
                    static_cast<uint16_t>(port))) {
                return false;
            }
        } else if (!add_or_error(L"PktmonInterfaceTcp", PKTMON_PROTO_TCP, 0, 0)) {
            return false;
        }
    }

    if (contains_case_insensitive(lower, "udp")) {
        int port = extract_port_after(lower, "udp port");
        if (port > 65535) {
            if (error != nullptr) {
                *error = "udp port is outside the valid range";
            }
            return false;
        }
        if (port > 0) {
            if (!add_or_error(
                    L"PktmonInterfaceUdpSource",
                    PKTMON_PROTO_UDP,
                    static_cast<uint16_t>(port),
                    0) ||
                !add_or_error(
                    L"PktmonInterfaceUdpDestination",
                    PKTMON_PROTO_UDP,
                    0,
                    static_cast<uint16_t>(port))) {
                return false;
            }
        } else if (!add_or_error(L"PktmonInterfaceUdp", PKTMON_PROTO_UDP, 0, 0)) {
            return false;
        }
    }

    return true;
}

std::string ipv4_to_string(const uint8_t* data) {
    char text[32];
    std::snprintf(text, sizeof(text), "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);
    return text;
}

std::string ipv6_to_string(const uint8_t* data) {
    char text[64];
    std::snprintf(
        text,
        sizeof(text),
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        data[0],
        data[1],
        data[2],
        data[3],
        data[4],
        data[5],
        data[6],
        data[7],
        data[8],
        data[9],
        data[10],
        data[11],
        data[12],
        data[13],
        data[14],
        data[15]);
    return text;
}

uint16_t read_be16(const uint8_t* data) {
    return static_cast<uint16_t>((data[0] << 8) | data[1]);
}

bool parse_ip_packet(const std::vector<uint8_t>& packet, size_t offset, ParsedPacket* out) {
    if (offset >= packet.size()) {
        return false;
    }
    const uint8_t version = packet[offset] >> 4;
    if (version == 4) {
        if (offset + 20 > packet.size()) {
            return false;
        }
        const uint8_t ihl = static_cast<uint8_t>((packet[offset] & 0x0f) * 4);
        if (ihl < 20 || offset + ihl > packet.size()) {
            return false;
        }
        const uint16_t total_length = read_be16(&packet[offset + 2]);
        const uint8_t proto = packet[offset + 9];
        size_t end = packet.size();
        if (total_length >= ihl && offset + total_length <= packet.size()) {
            end = offset + total_length;
        }
        size_t transport = offset + ihl;
        if (proto == PKTMON_PROTO_TCP) {
            if (transport + 20 > end) {
                return false;
            }
            const uint8_t tcp_header = static_cast<uint8_t>((packet[transport + 12] >> 4) * 4);
            if (tcp_header < 20 || transport + tcp_header > end) {
                return false;
            }
            out->source_port = read_be16(&packet[transport]);
            out->destination_port = read_be16(&packet[transport + 2]);
            out->payload.assign(packet.begin() + transport + tcp_header, packet.begin() + end);
        } else if (proto == PKTMON_PROTO_UDP) {
            if (transport + 8 > end) {
                return false;
            }
            out->source_port = read_be16(&packet[transport]);
            out->destination_port = read_be16(&packet[transport + 2]);
            out->payload.assign(packet.begin() + transport + 8, packet.begin() + end);
        } else {
            return false;
        }
        out->protocol = proto;
        out->source_address = ipv4_to_string(&packet[offset + 12]);
        out->destination_address = ipv4_to_string(&packet[offset + 16]);
        return true;
    }

    if (version == 6) {
        if (offset + 40 > packet.size()) {
            return false;
        }
        uint8_t proto = packet[offset + 6];
        const uint16_t payload_length = read_be16(&packet[offset + 4]);
        size_t end = offset + 40 + payload_length;
        if (end > packet.size()) {
            end = packet.size();
        }
        size_t transport = offset + 40;
        if (proto == PKTMON_PROTO_TCP) {
            if (transport + 20 > end) {
                return false;
            }
            const uint8_t tcp_header = static_cast<uint8_t>((packet[transport + 12] >> 4) * 4);
            if (tcp_header < 20 || transport + tcp_header > end) {
                return false;
            }
            out->source_port = read_be16(&packet[transport]);
            out->destination_port = read_be16(&packet[transport + 2]);
            out->payload.assign(packet.begin() + transport + tcp_header, packet.begin() + end);
        } else if (proto == PKTMON_PROTO_UDP) {
            if (transport + 8 > end) {
                return false;
            }
            out->source_port = read_be16(&packet[transport]);
            out->destination_port = read_be16(&packet[transport + 2]);
            out->payload.assign(packet.begin() + transport + 8, packet.begin() + end);
        } else {
            return false;
        }
        out->protocol = proto;
        out->source_address = ipv6_to_string(&packet[offset + 8]);
        out->destination_address = ipv6_to_string(&packet[offset + 24]);
        return true;
    }
    return false;
}

bool parse_packet_bytes(const std::vector<uint8_t>& bytes, double timestamp_unix, ParsedPacket* out) {
    if (bytes.empty() || out == nullptr) {
        return false;
    }
    out->timestamp_unix = timestamp_unix > 0.0 ? timestamp_unix : unix_time_now();

    if (parse_ip_packet(bytes, 0, out)) {
        return true;
    }
    if (bytes.size() >= 14) {
        uint16_t ethertype = read_be16(&bytes[12]);
        size_t offset = 14;
        if (ethertype == 0x8100 && bytes.size() >= 18) {
            ethertype = read_be16(&bytes[16]);
            offset = 18;
        }
        if ((ethertype == 0x0800 || ethertype == 0x86dd) && parse_ip_packet(bytes, offset, out)) {
            return true;
        }
    }
    for (size_t i = 0; i + 8 < bytes.size() && i < 128; ++i) {
        if (bytes[i] == 0xaa && bytes[i + 1] == 0xaa && bytes[i + 2] == 0x03 &&
            bytes[i + 3] == 0x00 && bytes[i + 4] == 0x00 && bytes[i + 5] == 0x00) {
            const uint16_t ethertype = read_be16(&bytes[i + 6]);
            const size_t offset = i + 8;
            if ((ethertype == 0x0800 || ethertype == 0x86dd) &&
                parse_ip_packet(bytes, offset, out)) {
                return true;
            }
        }
    }
    for (size_t i = 0; i + 20 < bytes.size() && i < 160; ++i) {
        const uint8_t version = bytes[i] >> 4;
        if ((version == 4 || version == 6) && parse_ip_packet(bytes, i, out)) {
            return true;
        }
    }
    return false;
}

void enqueue_packet(CaptureState* state, const std::vector<uint8_t>& bytes, double timestamp_unix = 0.0) {
    ParsedPacket packet;
    if (!parse_packet_bytes(bytes, timestamp_unix, &packet) || packet.payload.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->queue.size() >= 512) {
        state->queue.pop_front();
    }
    state->queue.push_back(std::move(packet));
    state->ready.notify_one();
}

double stream_descriptor_timestamp(const PACKETMONITOR_STREAM_DATA_DESCRIPTOR* descriptor) {
    if (descriptor == nullptr || descriptor->Data == nullptr ||
        descriptor->MetadataOffset == 0 ||
        descriptor->MetadataOffset + sizeof(PACKETMONITOR_STREAM_METADATA) > descriptor->DataSize) {
        return unix_time_now();
    }

    const auto* base = static_cast<const uint8_t*>(descriptor->Data);
    const auto* metadata = reinterpret_cast<const PACKETMONITOR_STREAM_METADATA*>(
        base + descriptor->MetadataOffset);
    return unix_time_from_system_time(metadata->TimeStamp.QuadPart);
}

void enqueue_stream_data(
    CaptureState* state,
    const PACKETMONITOR_STREAM_DATA_DESCRIPTOR* descriptor) {
    if (state == nullptr || descriptor == nullptr || descriptor->Data == nullptr ||
        descriptor->DataSize == 0) {
        return;
    }

    const auto* data = static_cast<const uint8_t*>(descriptor->Data);
    const uint32_t bounded_size = descriptor->DataSize > 262144 ? 262144 : descriptor->DataSize;
    const double timestamp = stream_descriptor_timestamp(descriptor);

    if (descriptor->PacketOffset < bounded_size) {
        uint32_t packet_size = bounded_size - descriptor->PacketOffset;
        if (descriptor->PacketLength > 0 && descriptor->PacketLength < packet_size) {
            packet_size = descriptor->PacketLength;
        }
        std::vector<uint8_t> packet_bytes(
            data + descriptor->PacketOffset,
            data + descriptor->PacketOffset + packet_size);
        enqueue_packet(state, packet_bytes, timestamp);
        return;
    }

    std::vector<uint8_t> bytes(data, data + bounded_size);
    enqueue_packet(state, bytes, timestamp);
}

void CALLBACK direct_packet_callback(
    void* context,
    const PACKETMONITOR_STREAM_DATA_DESCRIPTOR* descriptor) {
    auto* state = static_cast<CaptureState*>(context);
    if (state == nullptr || state->stopping.load()) {
        return;
    }
    enqueue_stream_data(state, descriptor);
}

void CALLBACK direct_event_callback(void* context, const void*, uint32_t event_type) {
    auto* state = static_cast<CaptureState*>(context);
    if (state == nullptr || event_type == 0) {
        return;
    }
}

template <typename T>
bool resolve_export(HMODULE module, const char* name, T* out, std::string* error) {
    FARPROC address = module != nullptr ? GetProcAddress(module, name) : nullptr;
    if (address == nullptr) {
        if (error != nullptr) {
            *error = std::string("missing PktMonApi export: ") + name;
        }
        return false;
    }
    *out = reinterpret_cast<T>(address);
    return true;
}

bool resolve_direct_api(HMODULE module, DirectApi* api, std::string* error) {
    return resolve_export(module, "PacketMonitorInitialize", &api->initialize, error) &&
           resolve_export(module, "PacketMonitorUninitialize", &api->uninitialize, error) &&
           resolve_export(module, "PacketMonitorCreateLiveSession", &api->create_session, error) &&
           resolve_export(module, "PacketMonitorCloseSessionHandle", &api->close_session, error) &&
           resolve_export(module, "PacketMonitorCreateRealtimeStream", &api->create_stream, error) &&
           resolve_export(module, "PacketMonitorCloseRealtimeStream", &api->close_stream, error) &&
           resolve_export(module, "PacketMonitorAttachOutputToSession", &api->attach_output, error) &&
           resolve_export(module, "PacketMonitorSetSessionActive", &api->set_active, error) &&
           resolve_export(
               module,
               "PacketMonitorAddCaptureConstraint",
               &api->add_capture_constraint,
               error);
}

void close_direct_capture(CaptureState* state) {
    if (state == nullptr) {
        return;
    }

    DirectApi api;
    if (state->pktmon_api != nullptr) {
        std::string ignored;
        resolve_direct_api(state->pktmon_api, &api, &ignored);
    }

    if (api.set_active != nullptr && state->session_handle != nullptr) {
        api.set_active(state->session_handle, FALSE);
    }
    if (api.close_stream != nullptr && state->stream_handle != nullptr) {
        api.close_stream(state->stream_handle);
    }
    state->stream_handle = nullptr;

    if (api.close_session != nullptr && state->session_handle != nullptr) {
        api.close_session(state->session_handle);
    }
    state->session_handle = nullptr;

    if (api.uninitialize != nullptr && state->api_handle != nullptr) {
        api.uninitialize(state->api_handle);
    }
    state->api_handle = nullptr;

    if (state->pktmon_api != nullptr) {
        FreeLibrary(state->pktmon_api);
        state->pktmon_api = nullptr;
    }
}

int32_t start_direct_capture(CaptureState* state, const std::string& packet_filter) {
    if (state == nullptr) {
        return PKTMON_E_INVALID_ARGUMENT;
    }

    HMODULE module = LoadLibraryW(L"PktMonApi.dll");
    if (module == nullptr) {
        set_error(state, "LoadLibrary(PktMonApi.dll) failed");
        return PKTMON_E_LOAD_DLL;
    }
    state->pktmon_api = module;

    DirectApi api;
    std::string error;
    if (!resolve_direct_api(module, &api, &error)) {
        set_error(state, error);
        close_direct_capture(state);
        return PKTMON_E_MISSING_EXPORT;
    }

    HRESULT hr = api.initialize(PACKETMONITOR_API_VERSION_1_0, nullptr, &state->api_handle);
    if (failed_hr(hr) || state->api_handle == nullptr) {
        set_error(state, hresult_message("PacketMonitorInitialize", hr));
        close_direct_capture(state);
        return PKTMON_E_PROCESS;
    }

    wchar_t session_name[64];
    std::swprintf(session_name, 64, L"PktmonInterface-%lu", GetCurrentProcessId());
    hr = api.create_session(state->api_handle, session_name, &state->session_handle);
    if (failed_hr(hr) || state->session_handle == nullptr) {
        set_error(state, hresult_message("PacketMonitorCreateLiveSession", hr));
        close_direct_capture(state);
        return PKTMON_E_PROCESS;
    }

    if (!configure_session_constraints(api, state->session_handle, packet_filter, &error)) {
        set_error(state, error);
        close_direct_capture(state);
        return PKTMON_E_PROCESS;
    }

    PACKETMONITOR_REALTIME_STREAM_CONFIGURATION config{};
    config.UserContext = state;
    config.EventCallback = direct_event_callback;
    config.DataCallback = direct_packet_callback;
    config.BufferSizeMultiplier = 4;
    config.TruncationSize = 9000;

    hr = api.create_stream(state->api_handle, &config, &state->stream_handle);
    if (failed_hr(hr) || state->stream_handle == nullptr) {
        set_error(state, hresult_message("PacketMonitorCreateRealtimeStream", hr));
        close_direct_capture(state);
        return PKTMON_E_PROCESS;
    }

    hr = api.attach_output(state->session_handle, state->stream_handle);
    if (failed_hr(hr)) {
        set_error(state, hresult_message("PacketMonitorAttachOutputToSession", hr));
        close_direct_capture(state);
        return PKTMON_E_PROCESS;
    }

    hr = api.set_active(state->session_handle, TRUE);
    if (failed_hr(hr)) {
        set_error(state, hresult_message("PacketMonitorSetSessionActive", hr));
        close_direct_capture(state);
        return PKTMON_E_PROCESS;
    }

    return PKTMON_OK;
}

void stop_capture(CaptureState* state) {
    if (state == nullptr) {
        return;
    }
    state->stopping.store(true);
    close_direct_capture(state);
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->started = false;
        state->queue.clear();
    }
    state->ready.notify_all();
}

}  // namespace

PKTMON_EXPORT int32_t PktmonVersion() {
    return kVersion;
}

PKTMON_EXPORT int32_t PktmonProbe(PktmonProbeInfo* info) {
    if (info == nullptr || info->struct_size != sizeof(PktmonProbeInfo)) {
        return PKTMON_E_INVALID_ARGUMENT;
    }

    ExportProbe probe = probe_exports();
    info->export_count = static_cast<uint32_t>(kPktmonExports.size());
    info->missing_count = static_cast<uint32_t>(probe.missing.size());
    const int32_t status =
        probe.module == nullptr
            ? PKTMON_E_LOAD_DLL
            : (probe.missing.empty() ? PKTMON_OK : PKTMON_E_MISSING_EXPORT);
    info->capture_ready = status == PKTMON_OK ? 1 : 0;
    info->reserved = 0;

    if (probe.module != nullptr) {
        FreeLibrary(probe.module);
    }
    return status;
}

PKTMON_EXPORT uint32_t PktmonGetExportReport(char* buffer, uint32_t buffer_size) {
    return copy_text(export_report(), buffer, buffer_size);
}

PKTMON_EXPORT PktmonHandle PktmonCreate() {
    return new (std::nothrow) CaptureState();
}

PKTMON_EXPORT void PktmonDestroy(PktmonHandle handle) {
    auto* state = static_cast<CaptureState*>(handle);
    if (state != nullptr) {
        stop_capture(state);
    }
    delete state;
}

PKTMON_EXPORT int32_t PktmonStart(PktmonHandle handle, const char* filter) {
    auto* state = static_cast<CaptureState*>(handle);
    if (state == nullptr) {
        return PKTMON_E_INVALID_ARGUMENT;
    }
    if (state->started) {
        return PKTMON_OK;
    }

    const std::string packet_filter = filter != nullptr ? filter : "";
    state->stopping.store(false);
    int32_t status = start_direct_capture(state, packet_filter);
    if (status != PKTMON_OK) {
        return status;
    }
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->started = true;
        state->last_error.clear();
    }
    return PKTMON_OK;
}

PKTMON_EXPORT int32_t PktmonRead(
    PktmonHandle handle,
    PktmonPacket* packet,
    uint32_t timeout_ms) {
    auto* state = static_cast<CaptureState*>(handle);
    if (state == nullptr || packet == nullptr ||
        packet->struct_size != sizeof(PktmonPacket)) {
        return PKTMON_E_INVALID_ARGUMENT;
    }

    std::unique_lock<std::mutex> lock(state->mutex);
    if (!state->started) {
        return PKTMON_E_NOT_STARTED;
    }
    if (state->queue.empty()) {
        state->ready.wait_for(lock, std::chrono::milliseconds(timeout_ms));
    }
    if (state->queue.empty()) {
        return PKTMON_E_TIMEOUT;
    }

    ParsedPacket item = std::move(state->queue.front());
    state->queue.pop_front();
    state->read_payload = std::move(item.payload);

    packet->timestamp_unix = item.timestamp_unix;
    packet->protocol = item.protocol;
    packet->source_port = item.source_port;
    packet->destination_port = item.destination_port;
    packet->payload = state->read_payload.data();
    packet->payload_size = static_cast<uint32_t>(state->read_payload.size());

    std::snprintf(packet->source_address, sizeof(packet->source_address), "%s", item.source_address.c_str());
    std::snprintf(
        packet->destination_address,
        sizeof(packet->destination_address),
        "%s",
        item.destination_address.c_str());
    return PKTMON_OK;
}

PKTMON_EXPORT void PktmonStop(PktmonHandle handle) {
    stop_capture(static_cast<CaptureState*>(handle));
}

PKTMON_EXPORT uint32_t PktmonLastError(
    PktmonHandle handle,
    char* buffer,
    uint32_t buffer_size) {
    auto* state = static_cast<CaptureState*>(handle);
    if (state == nullptr) {
        return copy_text("invalid capture handle", buffer, buffer_size);
    }
    std::lock_guard<std::mutex> lock(state->mutex);
    return copy_text(state->last_error, buffer, buffer_size);
}

