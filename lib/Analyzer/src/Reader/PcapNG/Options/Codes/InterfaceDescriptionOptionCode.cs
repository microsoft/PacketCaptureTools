// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options.Codes
{
    /// <summary>
    /// Interface description block options codes.
    /// </summary>
    internal enum InterfaceDescriptionOptionCode : ushort
    {
        /// <summary>
        /// End of options code.
        /// </summary>
        EndOfOptionsCode = 0,

        /// <summary>
        /// Comment option code.
        /// </summary>
        CommentCode = 1,

        /// <summary>
        /// Name option code.
        /// </summary>
        NameCode = 2,

        /// <summary>
        /// Description option code.
        /// </summary>
        DescriptionCode = 3,

        /// <summary>
        /// IPv4 Address option code.
        /// </summary>
        IPv4AddressCode = 4,

        /// <summary>
        /// IPv6 Address option code.
        /// </summary>
        IPv6AddressCode = 5,

        /// <summary>
        /// MAC Address option code.
        /// </summary>
        MacAddressCode = 6,

        /// <summary>
        /// EUI Address option code.
        /// </summary>
        EuiAddressCode = 7,

        /// <summary>
        /// Speed option code.
        /// </summary>
        SpeedCode = 8,

        /// <summary>
        /// Timestamp resolution option code.
        /// </summary>
        TimestampResolutionCode = 9,

        /// <summary>
        /// Time zone option code.
        /// </summary>
        TimeZoneCode = 10,

        /// <summary>
        /// Filter option code.
        /// </summary>
        FilterCode = 11,

        /// <summary>
        /// Operating system option code.
        /// </summary>
        OperatingSystemCode = 12,

        /// <summary>
        /// Frame check sequence option code.
        /// </summary>
        FrameCheckSequenceCode = 13,

        /// <summary>
        /// Time offset seconds option code.
        /// </summary>
        TimeOffsetSecondsCode = 14,
    }
}
