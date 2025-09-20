// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Direction;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States
{
    /// <summary>
    /// TDS connection closed after login ack state.
    /// </summary>
    internal class ConnectionClosedAfterLoginAckTdsState : FinalTdsState
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ConnectionClosedAfterLoginAckTdsState" /> class.
        /// </summary>
        /// <param name="packetFlowDetector">Packet flow detector.</param>
        public ConnectionClosedAfterLoginAckTdsState(IPacketFlowDetector packetFlowDetector)
            : base(packetFlowDetector)
        {
        }

        /// <inheritdoc />
        internal override TdsConnectionState TdsConnectionState => TdsConnectionState.ConnectionClosedAfterLoginAckTdsState;
    }
}
