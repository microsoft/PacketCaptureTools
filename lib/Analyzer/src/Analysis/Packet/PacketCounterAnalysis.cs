// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using System;
using System.Collections.Generic;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Packet;

/// <summary>
/// Total packet count, packet count per second and packet count per protocol analysis.
/// </summary>
public class PacketCounterAnalysis : IPacketAnalysis
{
    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly ISet<int> _tdsPorts;

    /// <summary>
    /// Initializes a new instance of the <see cref="PacketCounterAnalysis" /> class.
    /// </summary>
    /// <param name="packetFlowDetector">Packet flow detector.</param>
    /// <param name="tdsPorts">Tds ports.</param>
    public PacketCounterAnalysis(IPacketFlowDetector packetFlowDetector, ISet<int> tdsPorts)
        : this(packetFlowDetector, tdsPorts, 0)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PacketCounterAnalysis" /> class.
    /// </summary>
    /// <param name="packetFlowDetector">Packet flow detector.</param>
    /// <param name="tdsPorts">Tds ports.</param>
    /// <param name="globalPacketCount">Initial global packet count.</param>
    /// <param name="incomingTdsPacketCount">Initial incoming Tds packet count.</param>
    /// <param name="outgoingTdsPacketCount">Initial outgoing Tds packet count.</param>
    /// <param name="countByPhysicalFrameProtocol">Initial count by physical frame protocol.</param>
    /// <param name="incomingCountByNetworkPacketProtocol">Initial incoming count by network packet protocol.</param>
    /// <param name="outgoingCountByNetworkPacketProtocol">Initial outgoing count by network packet protocol.</param>
    /// <param name="incomingCountByTransportSegmentProtocol">Initial incoming count by transport packet protocol.</param>
    /// <param name="outgoingCountByTransportSegmentProtocol">Initial outgoing count by transport packet protocol.</param>
    /// <param name="countByTime">Initial count by time.</param>
    /// <param name="perIpPacketCounters">Initial per IP packet counters.</param>
    /// <exception cref="ArgumentNullException">Thrown when <see cref="IPAddress" /> or <see cref="ISet{T}" /> is null.</exception>
    internal PacketCounterAnalysis(
        IPacketFlowDetector packetFlowDetector,
        ISet<int> tdsPorts,
        int globalPacketCount = 0,
        int incomingTdsPacketCount = 0,
        int outgoingTdsPacketCount = 0,
        Dictionary<PhysicalFrameProtocol, int>? countByPhysicalFrameProtocol = default,
        Dictionary<NetworkPacketProtocol, int>? incomingCountByNetworkPacketProtocol = default,
        Dictionary<NetworkPacketProtocol, int>? outgoingCountByNetworkPacketProtocol = default,
        Dictionary<TransportSegmentProtocol, int>? incomingCountByTransportSegmentProtocol = default,
        Dictionary<TransportSegmentProtocol, int>? outgoingCountByTransportSegmentProtocol = default,
        Dictionary<DateTime, int>? countByTime = default,
        Dictionary<IPAddress, PerIpCounterMetrics>? perIpPacketCounters = default)
    {
        _packetFlowDetector = packetFlowDetector ?? throw new ArgumentNullException(nameof(packetFlowDetector));
        _tdsPorts = tdsPorts ?? throw new ArgumentNullException(nameof(tdsPorts));
        GlobalPacketCount = globalPacketCount;
        IncomingTdsPacketCount = incomingTdsPacketCount;
        OutgoingTdsPacketCount = outgoingTdsPacketCount;
        CountByPhysicalFrameProtocol = countByPhysicalFrameProtocol ?? Enum<PhysicalFrameProtocol>.AsDictionary(0);
        IncomingCountByNetworkPacketProtocol = incomingCountByNetworkPacketProtocol ?? Enum<NetworkPacketProtocol>.AsDictionary(0);
        OutgoingCountByNetworkPacketProtocol = outgoingCountByNetworkPacketProtocol ?? Enum<NetworkPacketProtocol>.AsDictionary(0);
        IncomingCountByTransportSegmentProtocol = incomingCountByTransportSegmentProtocol ?? Enum<TransportSegmentProtocol>.AsDictionary(0);
        OutgoingCountByTransportSegmentProtocol = outgoingCountByTransportSegmentProtocol ?? Enum<TransportSegmentProtocol>.AsDictionary(0);
        CountByTime = countByTime ?? [];
        PerIpPacketCounters = perIpPacketCounters ?? [];
    }

    /// <summary>
    /// Gets total packet count.
    /// </summary>
    public int GlobalPacketCount { get; private set; }

    /// <summary>
    /// Gets incoming Tds packet count.
    /// </summary>
    public int IncomingTdsPacketCount { get; private set; }

    /// <summary>
    /// Gets incoming Tds packet count.
    /// </summary>
    public int OutgoingTdsPacketCount { get; private set; }

    /// <summary>
    /// Gets packet Count per Physical Layer Protocol.
    /// </summary>
    public Dictionary<PhysicalFrameProtocol, int> CountByPhysicalFrameProtocol { get; }

    /// <summary>
    /// Gets incoming packet Count per Network Layer Protocol.
    /// </summary>
    public Dictionary<NetworkPacketProtocol, int> IncomingCountByNetworkPacketProtocol { get; }

    /// <summary>
    /// Gets outgoing packet Count per Network Layer Protocol.
    /// </summary>
    public Dictionary<NetworkPacketProtocol, int> OutgoingCountByNetworkPacketProtocol { get; }

    /// <summary>
    /// Gets incoming packet Count per Transport Layer Protocol.
    /// </summary>
    public Dictionary<TransportSegmentProtocol, int> IncomingCountByTransportSegmentProtocol { get; }

    /// <summary>
    /// Gets outgoing packet Count per Transport Layer Protocol.
    /// </summary>
    public Dictionary<TransportSegmentProtocol, int> OutgoingCountByTransportSegmentProtocol { get; }

    /// <summary>
    /// Gets the packet count per second.
    /// </summary>
    public Dictionary<DateTime, int> CountByTime { get; }

    /// <summary>
    /// Gets the packet counters per Ip as Total Packets, TCP Packets, Tds Packets.
    /// </summary>
    public Dictionary<IPAddress, PerIpCounterMetrics> PerIpPacketCounters { get; }

    /// <summary>
    /// Processes the packet by performing a Packet Router Analysis.
    /// This includes counting total number of packets, counting packets per protocol and packets per second.
    /// </summary>
    /// <param name="packet">Packet to be processed.</param>
    public void Process(CapturedPacket packet)
    {
        if (packet is null)
        {
            return;
        }

        GlobalPacketCount++;

        if (packet.PhysicalFrame?.Protocol != null)
        {
            CountByPhysicalFrameProtocol[packet.PhysicalFrame.Protocol]++;
        }

        ProcessCountByTime(packet.CapturedDateTime);

        if (packet.NetworkPacket == null)
        {
            return;
        }

        IPAddress remoteIpAddress;
        PacketDirection packetDirection = _packetFlowDetector.GetCapturedPacketDirection(packet);

        if (packetDirection == PacketDirection.Incoming)
        {
            remoteIpAddress = packet.NetworkPacket.SourceAddress;
        }
        else
        {
            remoteIpAddress = packet.NetworkPacket.DestinationAddress;
        }

        var isTdsPacket = ProcessTdsPacketCount(packet, packetDirection);

        var isTcpPacket = ProcessNetworkProtocolAndTransportSegmentCount(packet, packetDirection);

        ProcessPerIpPacketCounters(isTdsPacket, isTcpPacket, remoteIpAddress);
    }

    private void ProcessPerIpPacketCounters(bool isTdsPacket, bool isTcpPacket, IPAddress remoteIpAddress)
    {
        PerIpCounterMetrics currentIpMetrics;

        if (PerIpPacketCounters.TryGetValue(remoteIpAddress, out PerIpCounterMetrics? value))
        {
            currentIpMetrics = value;
        }
        else
        {
            currentIpMetrics = new PerIpCounterMetrics();
            PerIpPacketCounters.Add(remoteIpAddress, currentIpMetrics);
        }

        currentIpMetrics.TotalPacketCount++;

        if (isTdsPacket)
        {
            currentIpMetrics.TdsPacketCount++;
        }

        if (isTcpPacket)
        {
            currentIpMetrics.TcpPacketCount++;
        }
    }

    private void ProcessCountByTime(DateTime? packetCapturedDateTime)
    {
        if (packetCapturedDateTime is null)
        {
            return;
        }

        var capturedDateTime = packetCapturedDateTime.Value.TruncateToSeconds();

        if (!CountByTime.TryAdd(capturedDateTime, 1))
        {
            CountByTime[capturedDateTime]++;
        }
    }

    private bool ProcessTdsPacketCount(CapturedPacket packet, PacketDirection packetDirection)
    {
        if (packet.NetworkPacket?.TransportSegment == null)
        {
            return false;
        }

        if (packetDirection == PacketDirection.Outgoing &&
            _tdsPorts.Contains(packet.NetworkPacket.TransportSegment.SourcePort))
        {
            OutgoingTdsPacketCount++;
            return true;
        }

        if (packetDirection == PacketDirection.Incoming &&
            _tdsPorts.Contains(packet.NetworkPacket.TransportSegment.DestinationPort))
        {
            IncomingTdsPacketCount++;
            return true;
        }

        return false;
    }

    private bool ProcessNetworkProtocolAndTransportSegmentCount(CapturedPacket packet, PacketDirection packetDirection)
    {
        if (packet.NetworkPacket?.Protocol == null)
        {
            return false;
        }

        if (packetDirection == PacketDirection.Outgoing)
        {
            OutgoingCountByNetworkPacketProtocol[packet.NetworkPacket.Protocol]++;
            if (packet.TransportSegment?.Protocol != null)
            {
                OutgoingCountByTransportSegmentProtocol[packet.TransportSegment.Protocol]++;
            }
        }
        else
        {
            IncomingCountByNetworkPacketProtocol[packet.NetworkPacket.Protocol]++;
            if (packet.TransportSegment?.Protocol != null)
            {
                IncomingCountByTransportSegmentProtocol[packet.TransportSegment.Protocol]++;
            }
        }

        return packet.TransportSegment?.Protocol == TransportSegmentProtocol.TCP;
    }
}