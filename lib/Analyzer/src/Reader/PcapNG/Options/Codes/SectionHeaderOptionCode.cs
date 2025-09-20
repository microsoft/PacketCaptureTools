// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options.Codes
{
    /// <summary>
    /// Section header block option fields.
    /// </summary>
    internal enum SectionHeaderOptionCode : ushort
    {
        /// <summary>
        /// End of options field.
        /// </summary>
        EndOfOptionsCode = 0,

        /// <summary>
        /// Comment option field.
        /// </summary>
        CommentCode = 1,

        /// <summary>
        /// Hardware option field.
        /// </summary>
        HardwareCode = 2,

        /// <summary>
        /// Operating System option field.
        /// </summary>
        OperatingSystemCode = 3,

        /// <summary>
        /// User application option field.
        /// </summary>
        UserApplicationCode = 4,
    }
}
