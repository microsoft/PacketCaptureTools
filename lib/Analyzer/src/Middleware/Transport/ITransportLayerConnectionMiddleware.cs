// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport
{
    /// <summary>
    /// Transport connection middleware.
    /// </summary>
    public interface ITransportLayerConnectionMiddleware
    {
        /// <summary>
        /// Process <see cref="CapturedPacket" /> and get <see cref="TransportConnectionSnapshot" />.
        /// </summary>
        /// <param name="capturedPacket">Captured packet to process.</param>
        /// <returns>A connection snapshot after physical frame is processed.</returns>
        TransportConnectionSnapshot? ProcessPacket(CapturedPacket capturedPacket);
    }
}
