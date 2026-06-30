#pragma once

#include <windows.h>

#include <stdint.h>

constexpr uint32_t PACKETMONITOR_API_VERSION_1_0 = 0x00010000;
constexpr size_t PACKETMONITOR_MAX_NAME_LENGTH = 256;
constexpr size_t PACKETMONITOR_MAC_ADDRESS_SIZE = 6;
constexpr size_t PACKETMONITOR_IPV4_ADDRESS_SIZE = 4;
constexpr size_t PACKETMONITOR_IPV6_ADDRESS_SIZE = 16;

DECLARE_HANDLE(PACKETMONITOR_HANDLE);
DECLARE_HANDLE(PACKETMONITOR_SESSION);
DECLARE_HANDLE(PACKETMONITOR_REALTIME_STREAM);

enum PACKETMONITOR_DATA_SOURCE_KIND {
    PacketMonitorDataSourceKindAll,
    PacketMonitorDataSourceKindNetworkInterface,
};

union PACKETMONITOR_IP_ADDRESS {
    ULONG IPv4;
    UCHAR IPv4_bytes[PACKETMONITOR_IPV4_ADDRESS_SIZE];
    ULONGLONG IPv6[PACKETMONITOR_IPV6_ADDRESS_SIZE / sizeof(ULONGLONG)];
    UCHAR IPv6_bytes[PACKETMONITOR_IPV6_ADDRESS_SIZE];
};

struct PACKETMONITOR_PROTOCOL_CONSTRAINT {
    WCHAR Name[PACKETMONITOR_MAX_NAME_LENGTH];

    union {
        struct {
            UINT Mac1 : 1;
            UINT Mac2 : 1;
            UINT VlanId : 1;
            UINT EtherType : 1;
            UINT DSCP : 1;
            UINT TransportProtocol : 1;
            UINT Ip1 : 1;
            UINT Ip2 : 1;
            UINT IPv6 : 1;
            UINT PrefixLength1 : 1;
            UINT PrefixLength2 : 1;
            UINT Port1 : 1;
            UINT Port2 : 1;
            UINT TCPFlags : 1;
            UINT EncapType : 1;
            UINT VxLanPort : 1;
            UINT ClusterHeartbeat : 1;
        } IsPresent;
        UINT IsPresentValue;
    };

    UCHAR Mac1[PACKETMONITOR_MAC_ADDRESS_SIZE];
    UCHAR Mac2[PACKETMONITOR_MAC_ADDRESS_SIZE];
    USHORT VlanId;
    USHORT EtherType;
    USHORT DSCP;
    UCHAR TransportProtocol;
    PACKETMONITOR_IP_ADDRESS Ip1;
    PACKETMONITOR_IP_ADDRESS Ip2;
    UCHAR PrefixLength1;
    UCHAR PrefixLength2;
    USHORT Port1;
    USHORT Port2;
    UCHAR TCPFlags;
    ULONG EncapType;
    USHORT VxLanPort;
    UINT64 Packets;
    UINT64 Bytes;
};

enum PKTMON_PACKET_TYPE {
    PktMonPayload_Unknown,
    PktMonPayload_Ethernet,
    PktMonPayload_WiFi,
    PktMonPayload_IP,
    PktMonPayload_HTTP,
    PktMonPayload_TCP,
    PktMonPayload_UDP,
    PktMonPayload_ARP,
    PktMonPayload_ICMP,
    PktMonPayload_ESP,
    PktMonPayload_AH,
    PktMonPayload_L4Payload,
};

struct PACKETMONITOR_STREAM_METADATA {
    UINT64 PktGroupId;
    UINT16 PktCount;
    UINT16 AppearanceCount;
    UINT16 DirectionName;
    UINT16 PacketType;
    UINT16 ComponentId;
    UINT16 EdgeId;
    UINT16 Reserved;
    UINT32 DropReason;
    UINT32 DropLocation;
    UINT16 Processor;
    LARGE_INTEGER TimeStamp;
};

struct PACKETMONITOR_STREAM_DATA_DESCRIPTOR {
    VOID const* Data;
    UINT32 DataSize;
    UINT32 MetadataOffset;
    UINT32 PacketOffset;
    UINT32 PacketLength;
    UINT32 MissedPacketWriteCount;
    UINT32 MissedPacketReadCount;
};

using PACKETMONITOR_STREAM_EVENT_CALLBACK = VOID(CALLBACK*)(
    VOID* context,
    VOID const* streamEventInfo,
    UINT32 eventKind);

using PACKETMONITOR_STREAM_DATA_CALLBACK = VOID(CALLBACK*)(
    VOID* context,
    PACKETMONITOR_STREAM_DATA_DESCRIPTOR const* data);

struct PACKETMONITOR_REALTIME_STREAM_CONFIGURATION {
    VOID* UserContext;
    PACKETMONITOR_STREAM_EVENT_CALLBACK EventCallback;
    PACKETMONITOR_STREAM_DATA_CALLBACK DataCallback;
    UINT16 BufferSizeMultiplier;
    UINT16 TruncationSize;
};

