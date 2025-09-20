// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Timings;
using Microsoft.PacketCapture.Analyzer.Analysis.Metrics;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using System;
using System.Collections.Generic;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Test.Common;

internal static class AnalysisFixtureFactory
{
    internal static PacketCounterAnalysis GetPacketCounterAnalysis(
        IPacketFlowDetector? packetFlowDetector = null,
        ISet<int>? tdsPorts = null,
        int globalPacketCount = 0,
        int incomingTdsPacketCount = 0,
        int outgoingTdsPacketCount = 0,
        Dictionary<PhysicalFrameProtocol, int>? countByPhysicalFrameProtocol = null,
        Dictionary<NetworkPacketProtocol, int>? incomingCountByNetworkPacketProtocol = null,
        Dictionary<NetworkPacketProtocol, int>? outgoingCountByNetworkPacketProtocol = null,
        Dictionary<TransportSegmentProtocol, int>? incomingCountByTransportSegmentProtocol = null,
        Dictionary<TransportSegmentProtocol, int>? outgoingCountByTransportSegmentProtocol = null,
        Dictionary<DateTime, int>? countByTime = null,
        Dictionary<IPAddress, PerIpCounterMetrics>? perIpPacketCounters = null)
    {
        return new PacketCounterAnalysis(
            packetFlowDetector: packetFlowDetector ?? new ReferenceIpPacketFlowDetector(new HashSet<IPAddress> { IPAddress.Any }),
            tdsPorts: tdsPorts ?? new HashSet<int> { 1 },
            globalPacketCount: globalPacketCount,
            incomingTdsPacketCount: incomingTdsPacketCount,
            outgoingTdsPacketCount: outgoingTdsPacketCount,
            countByPhysicalFrameProtocol: countByPhysicalFrameProtocol,
            incomingCountByNetworkPacketProtocol: incomingCountByNetworkPacketProtocol,
            outgoingCountByNetworkPacketProtocol: outgoingCountByNetworkPacketProtocol,
            incomingCountByTransportSegmentProtocol: incomingCountByTransportSegmentProtocol,
            outgoingCountByTransportSegmentProtocol: outgoingCountByTransportSegmentProtocol,
            countByTime: countByTime,
            perIpPacketCounters: perIpPacketCounters);
    }

    internal static TcpConnectionRetransmissionAnalysis GetTcpConnectionRetransmissionAnalysis(
        Dictionary<IPAddress, int>? retransmissionsByIpAddress = null,
        Dictionary<DateTime, int>? retransmissionsByTime = null)
    {
        return new TcpConnectionRetransmissionAnalysis(
            retransmissionsByIpAddress: retransmissionsByIpAddress,
            retransmissionsByTime: retransmissionsByTime);
    }

    internal static TcpConnectionCounterAnalysis GetTcpConnectionCounterAnalysis(
        Dictionary<IPAddress, TcpConnectionCounterMetrics>? initialMetrics = null,
        Dictionary<TransportLayerConnection, TcpConnectionCounterMetrics>? initialTransportConnectionMetrics = null)
    {
        return new TcpConnectionCounterAnalysis(
            initialIpAggregatedMetrics: initialMetrics,
            initialTcpConnectionMetrics: initialTransportConnectionMetrics);
    }

    internal static TcpPacketResetAnalysis GetTcpPacketResetAnalysis(
        IPacketFlowDetector? packetFlowDetector = null,
        int globalCount = 0,
        Dictionary<(IPAddress sourceAddress, IPAddress destinationAddress, int sourcePort, int destinationPort),
            int>? countByConnection = null,
        Dictionary<DateTime, int>? countBySecond = null,
        Dictionary<IPAddress, (int asSource, int asDestination)>? perIpResetCount = null)
    {
        return new TcpPacketResetAnalysis(
            packetFlowDetector: packetFlowDetector ?? new ReferenceIpPacketFlowDetector(new HashSet<IPAddress> { IPAddress.Any }),
            globalCount: globalCount,
            countByConnection: countByConnection,
            countBySecond: countBySecond,
            perIpResetCount: perIpResetCount);
    }

    internal static TcpPercentageOfDataControlAnalysis GetTcpPercentageOfDataControlAnalysis(
        IPacketFlowDetector? packetFlowDetector = null,
        ulong outgoingTcpBytes = 0,
        ulong incomingTcpBytes = 0,
        ulong totalTcpDataTrafficBytesPassed = 0,
        ulong totalTcpControlTrafficBytesPassed = 0,
        Dictionary<DateTime, double>? percentageOfTcpDataPerSecond = null,
        Dictionary<DateTime, double>? percentageOfTcpControlPerSecond = null)
    {
        return new TcpPercentageOfDataControlAnalysis(
            packetFlowDetector: packetFlowDetector ?? new ReferenceIpPacketFlowDetector(new HashSet<IPAddress> { IPAddress.Any }),
            outgoingTcpBytes: outgoingTcpBytes,
            incomingTcpBytes: incomingTcpBytes,
            totalTcpDataTrafficBytesPassed: totalTcpDataTrafficBytesPassed,
            totalTcpControlTrafficBytesPassed: totalTcpControlTrafficBytesPassed,
            percentageOfTcpDataPerSecond: percentageOfTcpDataPerSecond,
            percentageOfTcpControlPerSecond: percentageOfTcpControlPerSecond);
    }

    internal static TcpConnectionTimingsAnalysis GetTcpConnectionTimingsAnalysis(
        Dictionary<TransportLayerConnection, DateTime>? handshakeStartTimes = null,
        Dictionary<TransportLayerConnection, DateTime>? connectionStartTimes = null,
        Dictionary<TransportLayerConnection, DateTime>? resetTimes = null,
        TimestampMetrics? handshakeDurations = null,
        TimestampMetrics? connectionDurations = null,
        TimestampMetrics? resetAndNextSynDurations = null)
    {
        return new TcpConnectionTimingsAnalysis(
            handshakeStartTimes: handshakeStartTimes,
            connectionStartTimes: connectionStartTimes,
            resetTimes: resetTimes,
            handshakeDurations: handshakeDurations,
            connectionDurations: connectionDurations,
            resetAndNextSynDurations: resetAndNextSynDurations);
    }

    internal static ThroughputAnalysis GetThroughputAnalysis(
        bool partialStartSlotSkipped = default,
        bool fullTimeSlotExists = default,
        long minNumberOfPackets = long.MaxValue,
        long maxNumberOfPackets = default,
        long minSpeedOfDataTransfer = long.MaxValue,
        long maxSpeedOfDataTransfer = default,
        long currentNumberOfPackets = default,
        long currentSizeOfPackets = default,
        DateTime? currentTimestampSecond = null,
        DateTime? earliestPacketTime = null,
        DateTime? latestPacketTime = null,
        long totalNumberOfPackets = default,
        long totalAmountOfBytesPassed = default)
    {
        return new ThroughputAnalysis(
            partialStartSlotSkipped,
            fullTimeSlotExists,
            minNumberOfPackets,
            maxNumberOfPackets,
            minSpeedOfDataTransfer,
            maxSpeedOfDataTransfer,
            currentNumberOfPackets,
            currentSizeOfPackets,
            currentTimestampSecond,
            earliestPacketTime,
            latestPacketTime,
            totalNumberOfPackets,
            totalAmountOfBytesPassed);
    }

    internal static TdsConnectionLatencyAnalysis GetTdsConnectionLatencyAnalysis(
        Dictionary<DateTime, TimestampMetrics>? tcpEstablishedToPreLoginLatencies = null,
        Dictionary<DateTime, TimestampMetrics>? preLoginToPreLoginResponseLatencies = null,
        Dictionary<DateTime, TimestampMetrics>? preLoginResponseToClientHelloLatencies = null,
        Dictionary<DateTime, TimestampMetrics>? clientHelloToServerHelloLatencies = null,
        Dictionary<DateTime, TimestampMetrics>? serverHelloToKeyExchangeLatencies = null,
        Dictionary<DateTime, TimestampMetrics>? keyExchangeToCipherChangeLatencies = null,
        Dictionary<DateTime, TimestampMetrics>? cipherChangeToLoginMessageLatencies = null,
        Dictionary<DateTime, TimestampMetrics>? loginMessageToLoginAckLatencies = null,
        Dictionary<DateTime, TimestampMetrics>? preLoginToLoginAckLatencies = null,
        Dictionary<DateTime, TimeSpan>? tcpEstablishedToPreLoginAverageLatencies = null,
        Dictionary<DateTime, TimeSpan>? preLoginToPreLoginResponseAverageLatencies = null,
        Dictionary<DateTime, TimeSpan>? preLoginResponseToClientHelloAverageLatencies = null,
        Dictionary<DateTime, TimeSpan>? clientHelloToServerHelloAverageLatencies = null,
        Dictionary<DateTime, TimeSpan>? serverHelloToKeyExchangeAverageLatencies = null,
        Dictionary<DateTime, TimeSpan>? keyExchangeToCipherChangeAverageLatencies = null,
        Dictionary<DateTime, TimeSpan>? cipherChangeToLoginMessageAverageLatencies = null,
        Dictionary<DateTime, TimeSpan>? loginMessageToLoginAckAverageLatencies = null,
        Dictionary<DateTime, TimeSpan>? preLoginToLoginAckAverageLatencies = null,
        Dictionary<TransportLayerConnection, List<TdsConnectionLatencyAnalysisMetrics>>? tdsConnectionLatencyAnalysisMetrics = null)
    {
        return new TdsConnectionLatencyAnalysis(
            tcpEstablishedToPreLoginLatencies,
            preLoginToPreLoginResponseLatencies,
            preLoginResponseToClientHelloLatencies,
            clientHelloToServerHelloLatencies,
            serverHelloToKeyExchangeLatencies,
            keyExchangeToCipherChangeLatencies,
            cipherChangeToLoginMessageLatencies,
            loginMessageToLoginAckLatencies,
            preLoginToLoginAckLatencies,
            tcpEstablishedToPreLoginAverageLatencies,
            preLoginToPreLoginResponseAverageLatencies,
            preLoginResponseToClientHelloAverageLatencies,
            clientHelloToServerHelloAverageLatencies,
            serverHelloToKeyExchangeAverageLatencies,
            keyExchangeToCipherChangeAverageLatencies,
            cipherChangeToLoginMessageAverageLatencies,
            loginMessageToLoginAckAverageLatencies,
            preLoginToLoginAckAverageLatencies,
            tdsConnectionLatencyAnalysisMetrics);
    }

    internal static TdsLoginConnectionAnalysis GetTdsLoginConnectionAnalysis(Dictionary<TransportLayerConnection, List<TdsLoginConnectionMetrics>>? connectionStates = null)
    {
        return new TdsLoginConnectionAnalysis(connectionStates);
    }
}