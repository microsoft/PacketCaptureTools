// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options.Codes
{
    /// <summary>
    /// Interface Statistics block Options.
    /// </summary>
    internal enum InterfaceStatisticsOptionCode : ushort
    {
        /// <summary>
        /// End of options.
        /// </summary>
        EndOfOptionsCode = 0,

        /// <summary>
        /// Comment option.
        /// </summary>
        CommentCode = 1,

        /// <summary>
        /// Start time option.
        /// </summary>
        StartTimeCode = 2,

        /// <summary>
        /// End time option.
        /// </summary>
        EndTimeCode = 3,

        /// <summary>
        /// Interface received option.
        /// </summary>
        InterfaceReceivedCode = 4,

        /// <summary>
        /// Interface drop option.
        /// </summary>
        InterfaceDropCode = 5,

        /// <summary>
        /// Filter accpted option.
        /// </summary>
        FilterAcceptCode = 6,

        /// <summary>
        /// System drop option.
        /// </summary>
        SystemDropCode = 7,

        /// <summary>
        /// Delivered to user option.
        /// </summary>
        DeliveredToUserCode = 8,
    }
}
