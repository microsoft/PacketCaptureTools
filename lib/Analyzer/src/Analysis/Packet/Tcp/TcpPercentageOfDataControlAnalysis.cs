// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;

/// <summary>
/// Analysis to determine Control and Data traffic of Tcp.
/// </summary>
public class TcpPercentageOfDataControlAnalysis : TcpPacketAnalysis
{
    private readonly IPacketFlowDetector _packetFlowDetector;
    private ulong _currentTcpDataTrafficBytes;
    private ulong _currentTcpControlTrafficBytes;
    private ulong _currentTcpBytes;

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpPercentageOfDataControlAnalysis" /> class.
    /// </summary>
    /// <param name="packetFlowDetector">Packet flow detector.</param>
    public TcpPercentageOfDataControlAnalysis(IPacketFlowDetector packetFlowDetector)
        : this(packetFlowDetector, 0)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpPercentageOfDataControlAnalysis" /> class.
    /// </summary>
    /// <param name="packetFlowDetector">Packet flow detector.</param>
    /// <param name="outgoingTcpBytes">Initial outgoing TCP bytes.</param>
    /// <param name="incomingTcpBytes">Initial incoming TCP bytes.</param>
    /// <param name="totalTcpDataTrafficBytesPassed">Initial total TCP data traffic bytes passed.</param>
    /// <param name="totalTcpControlTrafficBytesPassed">Initial total TCP control traffic bytes passed.</param>
    /// <param name="percentageOfTcpDataPerSecond">Initial percentage of TCP data per second.</param>
    /// <param name="percentageOfTcpControlPerSecond">Initial percentage of TCP control per second.</param>
    internal TcpPercentageOfDataControlAnalysis(
        IPacketFlowDetector packetFlowDetector,
        ulong outgoingTcpBytes = 0,
        ulong incomingTcpBytes = 0,
        ulong totalTcpDataTrafficBytesPassed = 0,
        ulong totalTcpControlTrafficBytesPassed = 0,
        Dictionary<DateTime, double>? percentageOfTcpDataPerSecond = default,
        Dictionary<DateTime, double>? percentageOfTcpControlPerSecond = default)
    {
        _packetFlowDetector = packetFlowDetector ?? throw new ArgumentNullException(nameof(packetFlowDetector));
        OutgoingTcpBytes = outgoingTcpBytes;
        IncomingTcpBytes = incomingTcpBytes;
        TotalTcpDataTrafficBytesPassed = totalTcpDataTrafficBytesPassed;
        TotalTcpControlTrafficBytesPassed = totalTcpControlTrafficBytesPassed;
        PercentageOfTcpDataPerSecond = percentageOfTcpDataPerSecond ?? new Dictionary<DateTime, double>();
        PercentageOfTcpControlPerSecond = percentageOfTcpControlPerSecond ?? new Dictionary<DateTime, double>();
    }

    /// <summary>
    /// Gets count of total Tcp packets.
    /// </summary>
    public ulong TotalTcpBytes => OutgoingTcpBytes + IncomingTcpBytes;

    /// <summary>
    /// Gets count of Tcp packets sent.
    /// </summary>
    public ulong OutgoingTcpBytes { get; private set; }

    /// <summary>
    /// Gets count of Tcp packets received.
    /// </summary>
    public ulong IncomingTcpBytes { get; private set; }

    /// <summary>
    /// Gets the total size of all TCP Data in bytes passed.
    /// </summary>
    public ulong TotalTcpDataTrafficBytesPassed { get; private set; }

    /// <summary>
    /// Gets the total size of all TCP Control in bytes passed.
    /// </summary>
    public ulong TotalTcpControlTrafficBytesPassed { get; private set; }

    /// <summary>
    /// Gets the percentage of Tcp packets which is data traffic.
    /// </summary>
    public double PercentageOfTcpData => TotalTcpBytes == 0 ? 0 : (double)TotalTcpDataTrafficBytesPassed / TotalTcpBytes;

    /// <summary>
    /// Gets the percentage of Tcp packets which is control traffic.
    /// </summary>
    public double PercentageOfTcpControl => TotalTcpBytes == 0 ? 0 : (double)TotalTcpControlTrafficBytesPassed / TotalTcpBytes;

    /// <summary>
    /// Gets the percentage of Tcp packets which is data traffic per second.
    /// </summary>
    public Dictionary<DateTime, double> PercentageOfTcpDataPerSecond { get; }

    /// <summary>
    /// Gets the percentage of Tcp packets which is data traffic per second.
    /// </summary>
    public Dictionary<DateTime, double> PercentageOfTcpControlPerSecond { get; }

    /// <summary>
    /// Processes the packet by performing a TCP Control Vs. TCP Data Analysis.
    /// This includes counting the size of the total TCP Control Traffic, TCP Data Traffic, the ratio of Control:Data and the ratio per second.
    /// </summary>
    /// <param name="packet">Captured packet containing date and time of capture.</param>
    /// <param name="ipPacket">IPv4 or IPv6 packet containing control size.</param>
    /// <param name="tcpSegment">TCP segment containing data size.</param>
    public override void Process(CapturedPacket packet, IpPacket ipPacket, TcpSegment tcpSegment)
    {
        if (packet?.CapturedDateTime is null ||
            tcpSegment is null)
        {
            return;
        }

        var tcpHeaderSize = tcpSegment.DataOffset;
        TotalTcpControlTrafficBytesPassed += tcpHeaderSize;

        var tcpPayloadSize = checked((uint)tcpSegment.NonTruncatedPayloadLength);
        TotalTcpDataTrafficBytesPassed += tcpPayloadSize;

        PacketDirection packetDirection = _packetFlowDetector.GetCapturedPacketDirection(packet);

        if (packetDirection == PacketDirection.Incoming)
        {
            IncomingTcpBytes += tcpPayloadSize + tcpHeaderSize;
        }
        else
        {
            OutgoingTcpBytes += tcpPayloadSize + tcpHeaderSize;
        }

        var capturedTimeSecond = packet.CapturedDateTime.Value.TruncateToSeconds();

        if (!PercentageOfTcpControlPerSecond.ContainsKey(capturedTimeSecond) || !PercentageOfTcpDataPerSecond.ContainsKey(capturedTimeSecond))
        {
            _currentTcpBytes = tcpPayloadSize + tcpHeaderSize;
            _currentTcpControlTrafficBytes = tcpHeaderSize;
            _currentTcpDataTrafficBytes = tcpPayloadSize;
        }
        else
        {
            _currentTcpBytes += tcpPayloadSize + tcpHeaderSize;
            _currentTcpControlTrafficBytes += tcpHeaderSize;
            _currentTcpDataTrafficBytes += tcpPayloadSize;
        }

        PercentageOfTcpControlPerSecond[capturedTimeSecond] = _currentTcpBytes == 0 ? 0 : (double)_currentTcpControlTrafficBytes / _currentTcpBytes;
        PercentageOfTcpDataPerSecond[capturedTimeSecond] = _currentTcpBytes == 0 ? 0 : (double)_currentTcpDataTrafficBytes / _currentTcpBytes;
    }
}
