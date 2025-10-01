// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Converter.Etl.Reader;
using Microsoft.PacketCapture.Converter.Packet;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;

namespace Microsoft.PacketCapture.Converter.Etl.Adapter;

/// <summary>
/// Adapter for converting etl events from <see cref="EventLogRecord" /> to <see cref="CapturedPacket" />.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="EventLogRecordPacketCaptureAdapter"/> class.
/// </remarks>
/// <param name="adapters">A list of concrete EventLogRecord adapters.</param>
public class EventLogRecordPacketCaptureAdapter(IEnumerable<ICapturedPacketAdapter<IEventLogRecordWrapper>> adapters) : ICapturedPacketAdapter<IEventLogRecordWrapper>
{

    /// <summary>
    /// Gets the underlying adapters in the EventLogRecord to CapturedPacket adapter.
    /// </summary>
    public IEnumerable<ICapturedPacketAdapter<IEventLogRecordWrapper>> Adapters { get; } = adapters ?? throw new ArgumentNullException(nameof(adapters));

    /// <summary>
    /// Converts EventLogRecord to a CapturedPacket.
    ///
    /// Since there are many etl providers for packet captures, every adapter in the
    /// compatible adapter list is tried.
    /// </summary>
    /// <param name="data">Any EventLogRecord.</param>
    /// <returns>Returns Captured packet, the event is supported and is a valid packet capture, otherwise returns null.</returns>
    public CapturedPacket? Convert(IEventLogRecordWrapper data)
    {
        if (data == null)
        {
            return null;
        }

        foreach (var adapter in Adapters)
        {
            var packet = adapter.Convert(data);
            if (packet != null)
            {
                return packet;
            }
        }

        return null;
    }
}