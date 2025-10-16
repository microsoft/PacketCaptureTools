// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Converter.Packet;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Microsoft.PacketCapture.Converter;

/// <inheritdoc/>
/// <summary>
/// Initializes a new instance of the <see cref="CaptureConverter"/> class.
/// </summary>
/// <param name="reader">Instance of <see cref="IPacketReader"/>.</param>
/// <param name="writer">Instance of <see cref="IPacketWriter"/>.</param>
public class CaptureConverter(IPacketReader reader, IPacketWriter writer) : ICaptureConverter
{
    private readonly IPacketReader _reader = reader ?? throw new ArgumentNullException(nameof(reader));
    private readonly IPacketWriter _writer = writer ?? throw new ArgumentNullException(nameof(writer));

    /// <inheritdoc/>
    public ConversionResult Convert()
    {
        var stopwatch = Stopwatch.StartNew();
        int packetCount = 0;
        var errors = new List<Exception>();

        while (_reader.HasNext())
        {
            try
            {
                CapturedPacket? packet = _reader.ReadNext();
                if (packet is not null)
                {
                    _writer.WritePacket(packet);
                    packetCount++;
                }
            }
            catch (Exception ex)
            {
                errors.Add(ex);
            }
        }

        return new ConversionResult(ElapsedTime: stopwatch.Elapsed, ConvertedPackets: packetCount, Errors: errors);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _reader.Dispose();
        _writer.Dispose();
        GC.SuppressFinalize(this);
    }
}
