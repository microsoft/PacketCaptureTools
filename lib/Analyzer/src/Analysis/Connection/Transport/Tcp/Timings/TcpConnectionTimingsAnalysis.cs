// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis.Metrics;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Timings;

/// <summary>
/// TCP connection timings analysis.
/// </summary>
public class TcpConnectionTimingsAnalysis : TcpConnectionAnalysis
{
    private readonly Dictionary<TransportLayerConnection, DateTime> _handshakeStartTimes;
    private readonly Dictionary<TransportLayerConnection, DateTime> _connectionStartTimes;
    private readonly Dictionary<TransportLayerConnection, DateTime> _resetTimes;

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpConnectionTimingsAnalysis" /> class.
    /// </summary>
    public TcpConnectionTimingsAnalysis()
        : this(default)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpConnectionTimingsAnalysis" /> class.
    /// </summary>
    /// <param name="handshakeStartTimes">Initial handshake start times.</param>
    /// <param name="connectionStartTimes">Initial connection start times.</param>
    /// <param name="resetTimes">Initial reset times.</param>
    /// <param name="handshakeDurations">Initial handshake durations.</param>
    /// <param name="connectionDurations">Initial connection durations.</param>
    /// <param name="resetAndNextSynDurations">Initial reset and next SYN durations.</param>
    internal TcpConnectionTimingsAnalysis(
        Dictionary<TransportLayerConnection, DateTime>? handshakeStartTimes = default,
        Dictionary<TransportLayerConnection, DateTime>? connectionStartTimes = default,
        Dictionary<TransportLayerConnection, DateTime>? resetTimes = default,
        TimestampMetrics? handshakeDurations = default,
        TimestampMetrics? connectionDurations = default,
        TimestampMetrics? resetAndNextSynDurations = default)
    {
        _handshakeStartTimes = handshakeStartTimes ?? new Dictionary<TransportLayerConnection, DateTime>();
        _connectionStartTimes = connectionStartTimes ?? new Dictionary<TransportLayerConnection, DateTime>();
        _resetTimes = resetTimes ?? new Dictionary<TransportLayerConnection, DateTime>();
        HandshakeDurations = handshakeDurations ?? new TimestampMetrics();
        ConnectionDurations = connectionDurations ?? new TimestampMetrics();
        ResetAndNextSynDurations = resetAndNextSynDurations ?? new TimestampMetrics();
    }

    /// <summary>
    /// Gets Connection handshake durations.
    /// </summary>
    public TimestampMetrics HandshakeDurations { get; }

    /// <summary>
    /// Gets Connection durations.
    /// </summary>
    public TimestampMetrics ConnectionDurations { get; }

    /// <summary>
    /// Gets Connection durations.
    /// </summary>
    public TimestampMetrics ResetAndNextSynDurations { get; }

    /// <inheritdoc />
    public override void Process(CapturedPacket packet, TcpConnectionSnapshot tcpConnectionSnapshot)
    {
        if (packet?.CapturedDateTime is not DateTime timestamp)
        {
            return;
        }

        ProcessConnectionHandshakeDuration(timestamp, tcpConnectionSnapshot);
        ProcessResetSynFlagDuration(timestamp, tcpConnectionSnapshot);
        ProcessConnectionDuration(timestamp, tcpConnectionSnapshot);
    }

    private void ProcessResetSynFlagDuration(DateTime packetTime, TcpConnectionSnapshot tcpConnectionSnapshot)
    {
        if (tcpConnectionSnapshot.LastPacketTcpFlags.Rst)
        {
            _resetTimes[tcpConnectionSnapshot.TransportConnection] = packetTime;
        }

        if (tcpConnectionSnapshot.LastPacketTcpFlags.Syn &&
            _resetTimes.ContainsKey(tcpConnectionSnapshot.TransportConnection))
        {
            ResetAndNextSynDurations.Insert(packetTime - _resetTimes[tcpConnectionSnapshot.TransportConnection]);
            _resetTimes.Remove(tcpConnectionSnapshot.TransportConnection);
        }
    }

    private void ProcessConnectionDuration(DateTime packetTime, TcpConnectionSnapshot tcpConnectionSnapshot)
    {
        switch (tcpConnectionSnapshot.TcpConnectionState)
        {
            case TcpConnectionState.SynSent:
                _connectionStartTimes[tcpConnectionSnapshot.TransportConnection] = packetTime;

                break;
            case TcpConnectionState.Closed:
                if (_connectionStartTimes.ContainsKey(tcpConnectionSnapshot.TransportConnection))
                {
                    ConnectionDurations.Insert(packetTime - _connectionStartTimes[tcpConnectionSnapshot.TransportConnection]);
                    _connectionStartTimes.Remove(tcpConnectionSnapshot.TransportConnection);
                }

                break;
        }
    }

    private void ProcessConnectionHandshakeDuration(DateTime packetTime, TcpConnectionSnapshot tcpConnectionSnapshot)
    {
        switch (tcpConnectionSnapshot.TcpConnectionState)
        {
            case TcpConnectionState.SynSent:
                _handshakeStartTimes[tcpConnectionSnapshot.TransportConnection] = packetTime;

                break;
            case TcpConnectionState.Established:
                if (_handshakeStartTimes.ContainsKey(tcpConnectionSnapshot.TransportConnection))
                {
                    HandshakeDurations.Insert(packetTime - _handshakeStartTimes[tcpConnectionSnapshot.TransportConnection]);
                    _handshakeStartTimes.Remove(tcpConnectionSnapshot.TransportConnection);
                }

                break;
            case TcpConnectionState.Closed:
                if (_handshakeStartTimes.ContainsKey(tcpConnectionSnapshot.TransportConnection))
                {
                    _handshakeStartTimes.Remove(tcpConnectionSnapshot.TransportConnection);
                }

                break;
        }
    }
}
