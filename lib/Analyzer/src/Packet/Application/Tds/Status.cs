// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Application.Tds
{
    /// <summary>
    /// TDS protocol message status.
    /// </summary>
    internal enum Status
    {
        /// <summary>
        /// Normal message.
        /// </summary>
        Normal = 0x00,

        /// <summary>
        /// End of message. The packet is the last packet in the whole request.
        /// </summary>
        EndOfMessage = 0x01,

        /// <summary>
        /// Ignore event from client to server. <see cref="EndOfMessage" /> must also be set.
        /// </summary>
        IgnoreEvent = 0x02,

        /// <summary>
        /// Reset connection before processing event.
        /// </summary>
        ResetConnection = 0x08,

        /// <summary>
        /// Reset connection before processing event but do not modify the transaction state.
        /// </summary>
        ResetConnectionSkipTransaction = 0x10,
    }
}
