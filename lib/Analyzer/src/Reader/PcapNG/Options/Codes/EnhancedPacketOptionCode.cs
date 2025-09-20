// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options.Codes
{
    /// <summary>
    /// Enhanced packet option codes.
    /// </summary>
    internal enum EnhancedPacketOptionCode : ushort
    {
        /// <summary>
        /// End of options option code.
        /// </summary>
        EndOfOptionsCode = 0,

        /// <summary>
        /// Comment option code.
        /// </summary>
        CommentCode = 1,

        /// <summary>
        /// Packet flag option code.
        /// </summary>
        PacketFlagCode = 2,

        /// <summary>
        /// Hash option code.
        /// </summary>
        HashCode = 3,

        /// <summary>
        /// Drop count option code.
        /// </summary>
        DropCountCode = 4,
    }
}
