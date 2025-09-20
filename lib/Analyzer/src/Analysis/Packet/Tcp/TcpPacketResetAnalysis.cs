// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using System;
using System.Collections.Generic;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;

/// <summary>
/// Analysis of TCP Resets.
/// </summary>
public class TcpPacketResetAnalysis : TcpPacketAnalysis
{
    private readonly IPacketFlowDetector _packetFlowDetector;

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpPacketResetAnalysis" /> class.
    /// </summary>
    /// <param name="packetFlowDetector">Packet flow detector.</param>
    public TcpPacketResetAnalysis(IPacketFlowDetector packetFlowDetector)
        : this(packetFlowDetector, 0)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpPacketResetAnalysis" /> class.
    /// </summary>
    /// <param name="packetFlowDetector">Packet flow detector.</param>
    /// <param name="globalCount">Initial global count.</param>
    /// <param name="countByConnection">Initial count by connection dictionary.</param>
    /// <param name="countBySecond">Initial count by second dictionary.</param>
    /// <param name="perIpResetCount">Initial count by per IP dictionary.</param>
    internal TcpPacketResetAnalysis(
        IPacketFlowDetector packetFlowDetector,
        int globalCount = 0,
        Dictionary<(IPAddress sourceAddress, IPAddress destinationAddress, int sourcePort, int destinationPort), int>? countByConnection = default,
        Dictionary<DateTime, int>? countBySecond = default,
        Dictionary<IPAddress, (int asSource, int asDestination)>? perIpResetCount = default)
    {
        _packetFlowDetector = packetFlowDetector ?? throw new ArgumentNullException(nameof(packetFlowDetector));
        GlobalCount = globalCount;
        CountByConnection = countByConnection ?? new Dictionary<(IPAddress sourceAddress, IPAddress destinationAddress, int sourcePort, int destinationPort), int>();
        CountBySecond = countBySecond ?? new Dictionary<DateTime, int>();
        PerIpResetCount = perIpResetCount ?? new Dictionary<IPAddress, (int asSource, int asDestination)>();
    }

    /// <summary>
    /// Gets total number of TCP resets.
    /// </summary>
    public int GlobalCount { get; private set; }

    /// <summary>
    /// Gets a dictionary that contains a mapping between connections and the reset count.
    /// </summary>
    public Dictionary<(IPAddress sourceAddress, IPAddress destinationAddress, int sourcePort, int destinationPort), int> CountByConnection { get; }

    /// <summary>
    /// Gets a dictionary that contains a mapping between remote IP and the reset count.
    /// </summary>
    public Dictionary<IPAddress, (int asSource, int asDestination)> PerIpResetCount { get; }

    /// <summary>
    /// Gets a dictionary containing a reset count per second.
    /// Only seconds when packets were transmitted are present in the dictionary, seconds without packets will not appear in the data.
    /// </summary>
    public Dictionary<DateTime, int> CountBySecond { get; }

    /// <summary>
    /// Processes the packet by performing a TCP Reset Analysis.
    /// This includes counting the number of TCP Resets, recording number of resets by IP and recording number of resets by Time.
    /// </summary>
    /// <param name="packet">Captured packet containing date and time of capture.</param>
    /// <param name="ipPacket">IPv4 or IPv6 packet to be processed.</param>
    /// <param name="tcpSegment">TCP segment to be processed.</param>
    public override void Process(CapturedPacket packet, IpPacket ipPacket, TcpSegment tcpSegment)
    {
        if (packet?.CapturedDateTime is null ||
            ipPacket is null ||
            tcpSegment is null)
        {
            return;
        }

        var reset = tcpSegment.Flags.Rst ? 1 : 0;
        GlobalCount += reset;

        if (reset > 0)
        {
            AddPacketIpResetCount(packet, reset);
        }

        var identifier = (ipPacket.SourceAddress, ipPacket.DestinationAddress, tcpSegment.SourcePort, tcpSegment.DestinationPort);

        if (!CountByConnection.ContainsKey(identifier))
        {
            CountByConnection.Add(identifier, reset);
        }
        else
        {
            CountByConnection[identifier] += reset;
        }

        var capturedTimeSecond = packet.CapturedDateTime.Value.TruncateToSeconds();

        if (!CountBySecond.ContainsKey(capturedTimeSecond))
        {
            CountBySecond.Add(capturedTimeSecond, reset);
        }
        else
        {
            CountBySecond[capturedTimeSecond] += reset;
        }
    }

    private void AddPacketIpResetCount(CapturedPacket packet, int reset)
    {
        if (packet.NetworkPacket == null)
        {
            return;
        }

        IPAddress remoteIpAddress;
        var isRemoteSourceReset = false;
        PacketDirection packetDirection = _packetFlowDetector.GetCapturedPacketDirection(packet);

        if (packetDirection == PacketDirection.Incoming)
        {
            remoteIpAddress = packet.NetworkPacket.SourceAddress;
            isRemoteSourceReset = true;
        }
        else
        {
            remoteIpAddress = packet.NetworkPacket.DestinationAddress;
        }

        (int asSource, int asDestination) ipResetCounts = PerIpResetCount.ContainsKey(remoteIpAddress)
            ? PerIpResetCount[remoteIpAddress]
            : (0, 0);

        if (isRemoteSourceReset)
        {
            ipResetCounts.asSource += reset;
        }
        else
        {
            ipResetCounts.asDestination += reset;
        }

        PerIpResetCount[remoteIpAddress] = ipResetCounts;
    }
}
