// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options.Codes;
using System.IO;
using System.Text;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options;

/// <summary>
/// Section header block options.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="SectionHeaderOption" /> class.
/// </remarks>
/// <param name="binaryReader">Binary reader with Section header block option bytes.</param>
/// <param name="optionsBlockSize">The size of the options block in bytes.</param>
internal sealed class SectionHeaderOption(BinaryReader binaryReader, int optionsBlockSize) : Option(binaryReader, optionsBlockSize)
{

    /// <summary>
    /// Gets a UTF-8 string containing a comment that is associated to the current block.
    /// </summary>
    public string? Comment
    {
        get
        {
            var bytes = GetOption((ushort)SectionHeaderOptionCode.CommentCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }

    /// <summary>
    /// Gets a UTF-8 string containing the description of the hardware used to create this section.
    /// </summary>
    public string? Hardware
    {
        get
        {
            var bytes = GetOption((ushort)SectionHeaderOptionCode.HardwareCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }

    /// <summary>
    /// Gets a UTF-8 string containing the name of the operating system used to create this section.
    /// </summary>
    public string? OperatingSystem
    {
        get
        {
            var bytes = GetOption((ushort)SectionHeaderOptionCode.OperatingSystemCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }

    /// <summary>
    /// Gets a UTF-8 string containing the name of the application used to create this section.
    /// </summary>
    public string? UserApplication
    {
        get
        {
            var bytes = GetOption((ushort)SectionHeaderOptionCode.UserApplicationCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }
}
