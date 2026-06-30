#include "../include/pktmon_backend.h"

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
#include <thread>
#include <vector>

namespace {

constexpr int32_t kVersion = 3;
constexpr uint32_t kPacketMonitorApiVersion = 0x00010000;

constexpr std::array<const char*, 20> kPktmonExports = {
    "PacketMonitorAddCaptureConstraint",
    "PacketMonitorAddSingleDataSourceToSession",
    "PacketMonitorAttachOutputToSession",
    "PacketMonitorCloseRealtimeStream",
    "PacketMonitorCloseSessionHandle",
    "PacketMonitorCreateLiveSession",
    "PacketMonitorCreateRealtimeStream",
    "PacketMonitorEnumDataSources",
    "PacketMonitorInitialize",
    "PacketMonitorSetSessionActive",
    "PacketMonitorUninitialize",
    "PktmonAddFilter",
    "PktmonGetComponentList",
    "PktmonGetFilterList",
    "PktmonGetStatus",
    "PktmonRemoveAllFilters",
    "PktmonResetCounters",
    "PktmonStart",
    "PktmonStop",
    "PktmonUnload",
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
    std::thread reader;
    std::atomic<bool> stopping = false;
    bool started = false;
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
    HANDLE stdout_read = nullptr;
    HANDLE stdout_write = nullptr;
    HMODULE pktmon_api = nullptr;
    void* api_handle = nullptr;
    void* session_handle = nullptr;
    void* stream_handle = nullptr;
    std::string last_error;
};

using FnPacketMonitorInitialize = long(WINAPI*)(uint32_t, void*, void**);
using FnPacketMonitorUninitialize = long(WINAPI*)(void*);
using FnPacketMonitorCreateLiveSession = long(WINAPI*)(void*, const wchar_t*, void**);
using FnPacketMonitorCloseSessionHandle = long(WINAPI*)(void*);
using FnPacketMonitorCreateRealtimeStream = long(WINAPI*)(void*, const void*, void**);
using FnPacketMonitorCloseRealtimeStream = long(WINAPI*)(void*);
using FnPacketMonitorAttachOutputToSession = long(WINAPI*)(void*, void*);
using FnPacketMonitorSetSessionActive = long(WINAPI*)(void*, BOOL);

struct DirectApi {
    FnPacketMonitorInitialize initialize = nullptr;
    FnPacketMonitorUninitialize uninitialize = nullptr;
    FnPacketMonitorCreateLiveSession create_session = nullptr;
    FnPacketMonitorCloseSessionHandle close_session = nullptr;
    FnPacketMonitorCreateRealtimeStream create_stream = nullptr;
    FnPacketMonitorCloseRealtimeStream close_stream = nullptr;
    FnPacketMonitorAttachOutputToSession attach_output = nullptr;
    FnPacketMonitorSetSessionActive set_active = nullptr;
};

struct DirectStreamConfig {
    void* context;
    void* event_callback;
    void* packet_callback;
    uint16_t queue_count;
    uint16_t packet_slots;
    uint32_t reserved;
};

static_assert(sizeof(DirectStreamConfig) == 0x20, "PktMonApi stream config ABI changed");

struct DirectPacketView {
    const uint8_t* data;
    uint32_t data_size;
    uint32_t reserved0;
    uint32_t packet_offset;
    uint32_t packet_size;
    uint32_t record_flags;
    uint32_t sequence;
};

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
    out << "{";
    out << "\"dll_loaded\":" << (probe.module != nullptr ? "true" : "false") << ",";
    out << "\"capture_ready\":true,";
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
    out << "\"note\":\"direct PktMonApi.dll realtime stream ABI is used first; ETL capture remains available as fallback diagnostics\"";
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

std::wstring widen(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    int count = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (count <= 0) {
        return std::wstring(text.begin(), text.end());
    }
    std::wstring output(static_cast<size_t>(count), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, output.data(), count);
    if (!output.empty() && output.back() == L'\0') {
        output.pop_back();
    }
    return output;
}

int run_pktmon_command(const std::wstring& arguments, std::string* output) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
        return static_cast<int>(GetLastError());
    }
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    std::wstring command = L"pktmon.exe " + arguments;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = write_pipe;
    si.hStdError = write_pipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessW(
        nullptr,
        command.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi);
    CloseHandle(write_pipe);
    if (!ok) {
        CloseHandle(read_pipe);
        return static_cast<int>(GetLastError());
    }

    std::string text;
    char buffer[4096];
    DWORD read = 0;
    while (ReadFile(read_pipe, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        text.append(buffer, buffer + read);
    }
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(read_pipe);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (output != nullptr) {
        *output = text;
    }
    return static_cast<int>(exit_code);
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

bool configure_filters(const std::string& filter, std::string* error) {
    std::string ignored;
    run_pktmon_command(L"filter remove", &ignored);

    std::vector<std::wstring> commands;
    if (contains_case_insensitive(filter, "tcp")) {
        int port = extract_port_after(filter, "tcp port");
        if (port <= 0) {
            port = extract_port_after(filter, "port");
        }
        std::wstringstream command;
        command << L"filter add PktmonInterfaceTcp -t TCP";
        if (port > 0) {
            command << L" -p " << port;
        }
        commands.push_back(command.str());
    }
    if (contains_case_insensitive(filter, "udp")) {
        int port = extract_port_after(filter, "udp port");
        std::wstringstream command;
        command << L"filter add PktmonInterfaceUdp -t UDP";
        if (port > 0) {
            command << L" -p " << port;
        }
        commands.push_back(command.str());
    }
    if (commands.empty()) {
        commands.push_back(L"filter add PktmonInterfaceAll");
    }

    for (const auto& command : commands) {
        std::string output;
        int code = run_pktmon_command(command, &output);
        if (code != 0) {
            if (error != nullptr) {
                *error = "pktmon filter command failed: " + output;
            }
            return false;
        }
    }
    return true;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bool is_hex_token(const std::string& token) {
    if (token.empty() || token.size() > 8) {
        return false;
    }
    for (char c : token) {
        if (hex_value(c) < 0) {
            return false;
        }
    }
    return true;
}

std::vector<uint8_t> parse_hex_line(const std::string& line) {
    std::vector<std::string> tokens;
    std::string token;
    for (char c : line) {
        if (hex_value(c) >= 0) {
            token.push_back(c);
        } else if (!token.empty()) {
            tokens.push_back(token);
            token.clear();
        }
    }
    if (!token.empty()) {
        tokens.push_back(token);
    }

    if (tokens.size() < 8) {
        return {};
    }
    size_t start = 0;
    if (tokens[0].size() > 2 && is_hex_token(tokens[0])) {
        start = 1;
    }

    std::vector<uint8_t> bytes;
    for (size_t i = start; i < tokens.size(); ++i) {
        if (tokens[i].size() != 2 || !is_hex_token(tokens[i])) {
            if (bytes.size() >= 8) {
                break;
            }
            bytes.clear();
            break;
        }
        bytes.push_back(static_cast<uint8_t>(
            (hex_value(tokens[i][0]) << 4) | hex_value(tokens[i][1])));
    }
    return bytes.size() >= 8 ? bytes : std::vector<uint8_t>();
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

bool parse_packet_bytes(const std::vector<uint8_t>& bytes, ParsedPacket* out) {
    if (bytes.empty() || out == nullptr) {
        return false;
    }
    out->timestamp_unix = unix_time_now();

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

void enqueue_packet(CaptureState* state, const std::vector<uint8_t>& bytes) {
    ParsedPacket packet;
    if (!parse_packet_bytes(bytes, &packet) || packet.payload.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->queue.size() >= 512) {
        state->queue.pop_front();
    }
    state->queue.push_back(std::move(packet));
    state->ready.notify_one();
}

void enqueue_direct_view(CaptureState* state, const DirectPacketView* view) {
    if (state == nullptr || view == nullptr || view->data == nullptr || view->data_size == 0) {
        return;
    }

    const uint32_t bounded_size = view->data_size > 262144 ? 262144 : view->data_size;
    std::vector<uint8_t> bytes(view->data, view->data + bounded_size);
    enqueue_packet(state, bytes);

    if (view->packet_offset > 0 && view->packet_offset < bounded_size) {
        uint32_t payload_size = bounded_size - view->packet_offset;
        if (view->packet_size > 0 && view->packet_size < payload_size) {
            payload_size = view->packet_size;
        }
        std::vector<uint8_t> packet_bytes(
            view->data + view->packet_offset,
            view->data + view->packet_offset + payload_size);
        enqueue_packet(state, packet_bytes);
    }
}

void WINAPI direct_packet_callback(void* context, const DirectPacketView* view) {
    auto* state = static_cast<CaptureState*>(context);
    if (state == nullptr || state->stopping.load()) {
        return;
    }
    enqueue_direct_view(state, view);
}

void WINAPI direct_event_callback(void* context, const void*, uint32_t event_type) {
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
           resolve_export(module, "PacketMonitorSetSessionActive", &api->set_active, error);
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

bool start_direct_capture(CaptureState* state) {
    if (state == nullptr) {
        return false;
    }

    HMODULE module = LoadLibraryW(L"PktMonApi.dll");
    if (module == nullptr) {
        set_error(state, "LoadLibrary(PktMonApi.dll) failed");
        return false;
    }
    state->pktmon_api = module;

    DirectApi api;
    std::string error;
    if (!resolve_direct_api(module, &api, &error)) {
        set_error(state, error);
        close_direct_capture(state);
        return false;
    }

    long hr = api.initialize(kPacketMonitorApiVersion, nullptr, &state->api_handle);
    if (failed_hr(hr) || state->api_handle == nullptr) {
        set_error(state, hresult_message("PacketMonitorInitialize", hr));
        close_direct_capture(state);
        return false;
    }

    wchar_t session_name[64];
    std::swprintf(session_name, 64, L"PktmonInterface-%lu", GetCurrentProcessId());
    hr = api.create_session(state->api_handle, session_name, &state->session_handle);
    if (failed_hr(hr) || state->session_handle == nullptr) {
        set_error(state, hresult_message("PacketMonitorCreateLiveSession", hr));
        close_direct_capture(state);
        return false;
    }

    DirectStreamConfig config{};
    config.context = state;
    config.event_callback = reinterpret_cast<void*>(&direct_event_callback);
    config.packet_callback = reinterpret_cast<void*>(&direct_packet_callback);
    config.queue_count = 4;
    config.packet_slots = 128;

    hr = api.create_stream(state->api_handle, &config, &state->stream_handle);
    if (failed_hr(hr) || state->stream_handle == nullptr) {
        set_error(state, hresult_message("PacketMonitorCreateRealtimeStream", hr));
        close_direct_capture(state);
        return false;
    }

    hr = api.attach_output(state->session_handle, state->stream_handle);
    if (failed_hr(hr)) {
        set_error(state, hresult_message("PacketMonitorAttachOutputToSession", hr));
        close_direct_capture(state);
        return false;
    }

    hr = api.set_active(state->session_handle, TRUE);
    if (failed_hr(hr)) {
        set_error(state, hresult_message("PacketMonitorSetSessionActive", hr));
        close_direct_capture(state);
        return false;
    }

    return true;
}

void reader_main(CaptureState* state) {
    std::string pending_line;
    std::vector<uint8_t> current_packet;
    char buffer[4096];
    DWORD read = 0;

    auto flush_packet = [&]() {
        if (!current_packet.empty()) {
            enqueue_packet(state, current_packet);
            current_packet.clear();
        }
    };

    while (!state->stopping.load()) {
        BOOL ok = ReadFile(state->stdout_read, buffer, sizeof(buffer), &read, nullptr);
        if (!ok || read == 0) {
            break;
        }
        for (DWORD i = 0; i < read; ++i) {
            char c = buffer[i];
            if (c == '\r') {
                continue;
            }
            if (c != '\n') {
                pending_line.push_back(c);
                continue;
            }

            std::vector<uint8_t> bytes = parse_hex_line(pending_line);
            if (!bytes.empty()) {
                current_packet.insert(current_packet.end(), bytes.begin(), bytes.end());
            } else {
                flush_packet();
                if (contains_case_insensitive(pending_line, "access is denied") ||
                    contains_case_insensitive(pending_line, "拒绝访问")) {
                    set_error(state, "pktmon requires an elevated Administrator process");
                }
            }
            pending_line.clear();
        }
    }
    flush_packet();
}

bool start_realtime_process(CaptureState* state) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&state->stdout_read, &state->stdout_write, &sa, 0)) {
        set_error(state, "CreatePipe failed");
        return false;
    }
    SetHandleInformation(state->stdout_read, HANDLE_FLAG_INHERIT, 0);

    std::wstring command =
        L"pktmon.exe start --capture --comp nics --pkt-size 0 --flags 0x10 --log-mode real-time";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = state->stdout_write;
    si.hStdError = state->stdout_write;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(
        nullptr,
        command.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi);
    CloseHandle(state->stdout_write);
    state->stdout_write = nullptr;
    if (!ok) {
        set_error(state, "CreateProcess(pktmon start) failed");
        CloseHandle(state->stdout_read);
        state->stdout_read = nullptr;
        return false;
    }
    state->process = pi.hProcess;
    state->thread = pi.hThread;
    state->reader = std::thread(reader_main, state);
    return true;
}

void close_process_handles(CaptureState* state) {
    if (state->stdout_write != nullptr) {
        CloseHandle(state->stdout_write);
        state->stdout_write = nullptr;
    }
    if (state->stdout_read != nullptr) {
        CloseHandle(state->stdout_read);
        state->stdout_read = nullptr;
    }
    if (state->thread != nullptr) {
        CloseHandle(state->thread);
        state->thread = nullptr;
    }
    if (state->process != nullptr) {
        CloseHandle(state->process);
        state->process = nullptr;
    }
}

void stop_capture(CaptureState* state) {
    if (state == nullptr) {
        return;
    }
    state->stopping.store(true);
    close_direct_capture(state);
    if (state->process != nullptr) {
        run_pktmon_command(L"stop", nullptr);
    }
    if (state->process != nullptr) {
        WaitForSingleObject(state->process, 3000);
        DWORD code = STILL_ACTIVE;
        GetExitCodeProcess(state->process, &code);
        if (code == STILL_ACTIVE) {
            TerminateProcess(state->process, 1);
        }
    }
    if (state->reader.joinable()) {
        state->reader.join();
    }
    run_pktmon_command(L"filter remove", nullptr);
    close_process_handles(state);
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
    info->capture_ready = 1;
    info->reserved = 0;

    const int32_t status =
        probe.module == nullptr
            ? PKTMON_E_LOAD_DLL
            : (probe.missing.empty() ? PKTMON_OK : PKTMON_E_MISSING_EXPORT);

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
    std::string error;
    if (!configure_filters(packet_filter, &error)) {
        set_error(state, error);
        return PKTMON_E_PROCESS;
    }

    state->stopping.store(false);
    char mode_buffer[32]{};
    DWORD mode_len = GetEnvironmentVariableA("PKTMON_BACKEND", mode_buffer, sizeof(mode_buffer));
    const bool use_exe_backend =
        mode_len > 0 && contains_case_insensitive(std::string(mode_buffer), "exe");
    if (use_exe_backend) {
        if (!start_realtime_process(state)) {
            run_pktmon_command(L"filter remove", nullptr);
            return PKTMON_E_PROCESS;
        }
    } else if (!start_direct_capture(state)) {
        run_pktmon_command(L"filter remove", nullptr);
        return PKTMON_E_PROCESS;
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

