// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;

/// <summary>
/// TDS protocol connection middleware.
/// </summary>
internal class TdsConnectionAnalysisMiddleware : IApplicationConnectionMiddleware
{
    private readonly IDictionary<TransportLayerConnection, TdsConnectionSnapshot> _tdsConnectionSnapshots;
    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly ISet<int> _tdsPorts;

    /// <summary>
    /// Initializes a new instance of the <see cref="TdsConnectionAnalysisMiddleware" /> class.
    /// </summary>
    /// <param name="packetFlowDetector">Packet flow detector.</param>
    /// <param name="tdsPorts">The target TDS ports.</param>
    internal TdsConnectionAnalysisMiddleware(IPacketFlowDetector packetFlowDetector, ISet<int> tdsPorts)
    {
        _packetFlowDetector = packetFlowDetector;
        _tdsPorts = tdsPorts;
        _tdsConnectionSnapshots = new Dictionary<TransportLayerConnection, TdsConnectionSnapshot>();
    }

    /// <inheritdoc />
    public ApplicationConnectionSnapshot? Process(CapturedPacket capturedPacket, TransportConnectionSnapshot transportConnectionSnapshot)
    {
        if (!IsValidConnectionAndPacket(
                capturedPacket: capturedPacket,
                transportConnectionSnapshot: transportConnectionSnapshot,
                out var tcpSegment,
                out var ipPacket,
                out var tcpConnectionSnapshot))
        {
            return null;
        }

        TdsConnectionSnapshot tdsConnectionSnapshot;
        TdsMessage? tdsMessage = null;
        TlsRecord? tlsRecord = null;

        if (tcpSegment.Payload?.Length > 0)
        {
            if (TdsMessage.TryParse(tcpSegment.Payload, 0, out tdsMessage) &&
                tdsMessage?.Payload.Length > 0)
            {
                TlsRecord.TryParse(tdsMessage.Payload, 0, out tlsRecord);
            }
            else
            {
                TlsRecord.TryParse(tcpSegment.Payload, 0, out tlsRecord);
            }
        }

        if (!_tdsConnectionSnapshots.ContainsKey(transportConnectionSnapshot.TransportConnection))
        {
            tdsConnectionSnapshot = new TdsConnectionSnapshot(
                ipPacket: ipPacket,
                segment: tcpSegment,
                tdsMessage: tdsMessage,
                tlsRecord: tlsRecord,
                tcpConnectionSnapshot: tcpConnectionSnapshot);

            _tdsConnectionSnapshots.Add(transportConnectionSnapshot.TransportConnection, tdsConnectionSnapshot);
        }
        else
        {
            tdsConnectionSnapshot = _tdsConnectionSnapshots[transportConnectionSnapshot.TransportConnection];
            tdsConnectionSnapshot.UpdateTdsConnectionSnapshot(ipPacket, tcpSegment, tdsMessage, tlsRecord);
        }

        return tdsConnectionSnapshot;
    }

    private bool IsValidConnectionAndPacket(
        CapturedPacket capturedPacket,
        TransportConnectionSnapshot transportConnectionSnapshot,
        [NotNullWhen(true)] out TcpSegment? tcpSegment,
        [NotNullWhen(true)] out IpPacket? ipPacket,
        [NotNullWhen(true)] out TcpConnectionSnapshot? tcpConnectionSnapshot)
    {
        tcpSegment = null;
        ipPacket = null;
        tcpConnectionSnapshot = null;

        if (capturedPacket?.NetworkPacket is not IpPacket validIpPacket)
        {
            return false;
        }

        if (capturedPacket.TransportSegment is not TcpSegment validTcpSegment ||
            (!IsOutgoingTdsConnection(validIpPacket, validTcpSegment.SourcePort) && !IsIncomingTdsConnection(validIpPacket, validTcpSegment.DestinationPort)))
        {
            return false;
        }

        if (transportConnectionSnapshot is not TcpConnectionSnapshot validTcpConnectionSnapshot)
        {
            return false;
        }

        tcpSegment = validTcpSegment;
        ipPacket = validIpPacket;
        tcpConnectionSnapshot = validTcpConnectionSnapshot;

        return true;
    }

    private bool IsOutgoingTdsConnection(NetworkPacket packet, int sourcePort)
    {
        return _tdsPorts.Contains(sourcePort) && _packetFlowDetector.GetNetworkPacketDirection(packet).Equals(PacketDirection.Outgoing);
    }

    private bool IsIncomingTdsConnection(NetworkPacket packet, int destinationPort)
    {
        return _tdsPorts.Contains(destinationPort) && _packetFlowDetector.GetNetworkPacketDirection(packet).Equals(PacketDirection.Incoming);
    }
}
