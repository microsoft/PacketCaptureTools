// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Direction;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States
{
    /// <summary>
    /// TDS connection closed state.
    /// </summary>
    internal class ConnectionClosedWithErrorTdsState : FinalTdsState
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ConnectionClosedWithErrorTdsState" /> class.
        /// </summary>
        /// <param name="packetFlowDetector">Packet flow detector.</param>
        public ConnectionClosedWithErrorTdsState(IPacketFlowDetector packetFlowDetector)
            : base(packetFlowDetector)
        {
        }

        /// <inheritdoc />
        internal override TdsConnectionState TdsConnectionState => TdsConnectionState.ClosedWithError;
    }
}
