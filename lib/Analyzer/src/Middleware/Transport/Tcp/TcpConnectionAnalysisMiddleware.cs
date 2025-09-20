// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp
{
    /// <summary>
    /// A middleware used to retrieve TCP connection snapshots.
    /// </summary>
    public class TcpConnectionAnalysisMiddleware : ITransportLayerConnectionMiddleware
    {
        private readonly IDictionary<TransportLayerConnection, TcpConnectionSnapshot> _tcpConnectionSnapshots;
        private readonly IPacketFlowDetector _packetFlowDetector;

        /// <summary>
        /// Initializes a new instance of the <see cref="TcpConnectionAnalysisMiddleware" /> class.
        /// </summary>
        /// <param name="packetFlowDetector">Packet flow detector.</param>
        public TcpConnectionAnalysisMiddleware(IPacketFlowDetector packetFlowDetector)
        {
            _packetFlowDetector = packetFlowDetector ?? throw new ArgumentNullException(nameof(packetFlowDetector));
            _tcpConnectionSnapshots = new Dictionary<TransportLayerConnection, TcpConnectionSnapshot>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TcpConnectionAnalysisMiddleware" /> class.
        /// </summary>
        /// <param name="packetFlowDetector">Packet flow detector.</param>
        /// <param name="tcpConnectionSnapshots">Initial TCP connection snapshot dictionary.</param>
        internal TcpConnectionAnalysisMiddleware(IPacketFlowDetector packetFlowDetector, IDictionary<TransportLayerConnection, TcpConnectionSnapshot> tcpConnectionSnapshots)
        {
            _packetFlowDetector = packetFlowDetector ?? throw new ArgumentNullException(nameof(packetFlowDetector));
            _tcpConnectionSnapshots = tcpConnectionSnapshots ?? throw new ArgumentNullException(nameof(tcpConnectionSnapshots));
        }

        /// <inheritdoc />
        public TransportConnectionSnapshot? ProcessPacket(CapturedPacket capturedPacket)
        {
            if (!(capturedPacket.PhysicalFrame is EthernetFrame physicalFrame && physicalFrame.NetworkPacket is IpPacket ipPacket && ipPacket.TransportSegment is TcpSegment tcpSegment))
            {
                return null;
            }

            var transportConnection = new TransportLayerConnection(
                sourceIpAddress: ipPacket.SourceAddress,
                destinationIpAddress: ipPacket.DestinationAddress,
                sourcePort: tcpSegment.SourcePort,
                destinationPort: tcpSegment.DestinationPort);

            TcpConnectionSnapshot tcpConnectionSnapshot;

            if (!_tcpConnectionSnapshots.ContainsKey(transportConnection))
            {
                tcpConnectionSnapshot = new TcpConnectionSnapshot(
                    ipPacket: ipPacket,
                    tcpSegment: tcpSegment,
                    transportConnection: transportConnection,
                    packetFlowDetector: _packetFlowDetector,
                    packetCaptureTimestamp: capturedPacket.CapturedDateTime);

                _tcpConnectionSnapshots.Add(transportConnection, tcpConnectionSnapshot);
            }
            else
            {
                tcpConnectionSnapshot = _tcpConnectionSnapshots[transportConnection];
                tcpConnectionSnapshot.UpdateTcpConnectionSnapshot(tcpSegment, ipPacket, capturedPacket.CapturedDateTime);
            }

            return tcpConnectionSnapshot;
        }
    }
}
