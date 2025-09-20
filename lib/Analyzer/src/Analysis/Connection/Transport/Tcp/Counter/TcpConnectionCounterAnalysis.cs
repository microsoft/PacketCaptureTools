// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using System;
using System.Collections.Generic;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;

/// <summary>
/// TCP connection counter analysis.
/// </summary>
public class TcpConnectionCounterAnalysis : TcpConnectionAnalysis
{
    private readonly Dictionary<TransportLayerConnection, TcpConnectionState> _tcpConnectionLastStates;

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpConnectionCounterAnalysis" /> class.
    /// </summary>
    public TcpConnectionCounterAnalysis()
        : this(default)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpConnectionCounterAnalysis" /> class.
    /// </summary>
    /// <param name="initialIpAggregatedMetrics">Initial TCP connection counter metrics aggregated per IP.</param>
    /// <param name="initialTcpConnectionMetrics">Initial TCP connection counter metrics.</param>
    internal TcpConnectionCounterAnalysis(
        Dictionary<IPAddress, TcpConnectionCounterMetrics>? initialIpAggregatedMetrics = default,
        Dictionary<TransportLayerConnection, TcpConnectionCounterMetrics>? initialTcpConnectionMetrics = default)
    {
        _tcpConnectionLastStates = [];
        TcpConnectionMetrics = initialTcpConnectionMetrics ?? [];
        IpAggregatedMetrics = initialIpAggregatedMetrics ?? [];
    }

    /// <summary>
    /// Gets TCP connection counter metrics.
    /// </summary>
    public Dictionary<TransportLayerConnection, TcpConnectionCounterMetrics> TcpConnectionMetrics { get; }

    /// <summary>
    /// Gets TCP connection counter metrics aggregated over IP addresses.
    /// </summary>
    public Dictionary<IPAddress, TcpConnectionCounterMetrics> IpAggregatedMetrics { get; }

    /// <inheritdoc />
    public override void Process(CapturedPacket packet, TcpConnectionSnapshot tcpConnectionSnapshot)
    {
        if (packet.NetworkPacket is null)
        {
            return;
        }

        if (!_tcpConnectionLastStates.TryGetValue(tcpConnectionSnapshot.TransportConnection, out TcpConnectionState tcpConnectionState))
        {
            tcpConnectionState = TcpConnectionState.Unknown;
            _tcpConnectionLastStates.Add(
                key: tcpConnectionSnapshot.TransportConnection,
                value: tcpConnectionState);
        }

        var remoteIpAddress = tcpConnectionSnapshot.GetRemoteIpAddress(packet.NetworkPacket);

        if (!TcpConnectionMetrics.TryGetValue(tcpConnectionSnapshot.TransportConnection, out TcpConnectionCounterMetrics? tcpConnectionCounterMetrics))
        {
            tcpConnectionCounterMetrics = new TcpConnectionCounterMetrics();
            TcpConnectionMetrics.Add(
                key: tcpConnectionSnapshot.TransportConnection,
                value: tcpConnectionCounterMetrics);

            if (!IpAggregatedMetrics.TryGetValue(remoteIpAddress, out TcpConnectionCounterMetrics? value))
            {
                IpAggregatedMetrics.Add(
                    key: remoteIpAddress,
                    value: new TcpConnectionCounterMetrics());
            }
            else
            {
                value.UniqueConnectionCount++;
            }
        }

        if (!IpAggregatedMetrics.TryGetValue(remoteIpAddress, out var ipAggregatedMetrics))
        {
            throw new Exception("Unable to determine tcp connection direction, ignoring packet.");
        }

        if (IsNewUniqueConnection(tcpConnectionSnapshot, tcpConnectionState))
        {
            tcpConnectionCounterMetrics.UniqueConnectionCount++;
            ipAggregatedMetrics.UniqueConnectionCount++;
        }

        if (IsNewEstablishedOrAssumedEstablishedState(tcpConnectionSnapshot, tcpConnectionState))
        {
            tcpConnectionCounterMetrics.EstablishedConnectionCount++;
            ipAggregatedMetrics.EstablishedConnectionCount++;
        }

        if (IsNewClosedState(tcpConnectionSnapshot, tcpConnectionState))
        {
            tcpConnectionCounterMetrics.ClosedConnectionCount++;
            ipAggregatedMetrics.ClosedConnectionCount++;
        }

        UpdateDirectionalCounters(tcpConnectionSnapshot, tcpConnectionCounterMetrics);
        UpdateDirectionalCounters(tcpConnectionSnapshot, ipAggregatedMetrics);

        tcpConnectionCounterMetrics.ProcessRoundTripTime(tcpConnectionSnapshot.LastRoundTripTime);
        ipAggregatedMetrics.ProcessRoundTripTime(tcpConnectionSnapshot.LastRoundTripTime);

        if (tcpConnectionState != tcpConnectionSnapshot.TcpConnectionState)
        {
            _tcpConnectionLastStates[tcpConnectionSnapshot.TransportConnection] = tcpConnectionSnapshot.TcpConnectionState;
        }
    }

    private static bool IsNewEstablishedOrAssumedEstablishedState(TcpConnectionSnapshot tcpConnectionSnapshot, TcpConnectionState lastTcpConnectionState)
    {
        return IsNewEstablishedState(tcpConnectionSnapshot, lastTcpConnectionState) ||
               IsNewAssumedEstablishedState(tcpConnectionSnapshot, lastTcpConnectionState);
    }

    private static bool IsNewEstablishedState(TcpConnectionSnapshot tcpConnectionSnapshot, TcpConnectionState lastTcpConnectionState)
    {
        return tcpConnectionSnapshot.TcpConnectionState == TcpConnectionState.Established &&
               lastTcpConnectionState != TcpConnectionState.Established;
    }

    private static bool IsNewAssumedEstablishedState(TcpConnectionSnapshot tcpConnectionSnapshot, TcpConnectionState lastTcpConnectionState)
    {
        return tcpConnectionSnapshot.TcpConnectionState == TcpConnectionState.AssumedEstablished &&
               lastTcpConnectionState != TcpConnectionState.AssumedEstablished;
    }

    private static bool IsNewClosedState(TcpConnectionSnapshot tcpConnectionSnapshot, TcpConnectionState lastTcpConnectionState)
    {
        return tcpConnectionSnapshot.TcpConnectionState == TcpConnectionState.Closed &&
               lastTcpConnectionState != TcpConnectionState.Closed;
    }

    private static bool IsNewUniqueConnection(TcpConnectionSnapshot tcpConnectionSnapshot, TcpConnectionState lastTcpConnectionState)
    {
        return tcpConnectionSnapshot.TcpConnectionState == TcpConnectionState.SynSent &&
               lastTcpConnectionState == TcpConnectionState.Closed;
    }

    private static void UpdateDirectionalCounters(TcpConnectionSnapshot tcpConnectionSnapshot, TcpConnectionCounterMetrics tcpConnectionCounterMetrics)
    {
        switch (tcpConnectionSnapshot.TcpConnectionState)
        {
            case TcpConnectionState.SynSent:
                UpdateNewConnectionRequestCounters(tcpConnectionCounterMetrics, tcpConnectionSnapshot.LastPacketDirection);
                break;

            case TcpConnectionState.FirstFinishSent:
                UpdateCloseConnectionRequestCounters(tcpConnectionCounterMetrics, tcpConnectionSnapshot.LastPacketDirection);
                break;
        }
    }

    private static void UpdateNewConnectionRequestCounters(TcpConnectionCounterMetrics tcpConnectionCounterMetrics, PacketDirection packetDirection)
    {
        switch (packetDirection)
        {
            case PacketDirection.Incoming:
                tcpConnectionCounterMetrics.RemoteNewConnectionRequestCount++;
                break;

            case PacketDirection.Outgoing:
                tcpConnectionCounterMetrics.ClientNewConnectionRequestCount++;
                break;
        }
    }

    private static void UpdateCloseConnectionRequestCounters(TcpConnectionCounterMetrics tcpConnectionCounterMetrics, PacketDirection packetDirection)
    {
        switch (packetDirection)
        {
            case PacketDirection.Incoming:
                tcpConnectionCounterMetrics.RemoteCloseConnectionRequestCount++;
                break;

            case PacketDirection.Outgoing:
                tcpConnectionCounterMetrics.ClientCloseConnectionRequestCount++;
                break;
        }
    }
}
