// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Converter.Etl.Reader;
using Microsoft.PacketCapture.Converter.Packet;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;

namespace Microsoft.PacketCapture.Converter.Etl.Adapter;

/// <summary>
/// A Pktmon etl event adapter for CapturedPacket.
/// </summary>
[SupportedOSPlatform("windows")]
public class PktmonEventAdapter : ICapturedPacketAdapter<IEventLogRecordWrapper>
{
    private static readonly DateTime MinEpochTime = new(1970, 1, 1);

    /// <summary>
    /// Converts given EventLogRecord to CapturedPacket if is a valid Pktmon event.
    /// </summary>
    /// <param name="eventLogRecord">Any EventLogRecord.</param>
    /// <returns>A <see cref="CapturedPacket"/> instance if <paramref name="eventLogRecord"/> a valid pktmon event, otherwise null.</returns>
    public CapturedPacket? Convert(IEventLogRecordWrapper eventLogRecord)
    {
        return IsValidPktMonPacket(eventLogRecord) ? ParseEventLogRecord(eventLogRecord) : null;
    }

    /// <summary>
    /// Checks whether the provided EventLogRecord is a valid PktMon packet.
    /// <br></br><br></br>
    /// Validity means it is:
    /// <list type="number">
    ///     <item>
    ///         <description>Not Null.</description>
    ///     </item>
    ///     <item>
    ///         <description>The PktMon provider ID matches the event's provider ID</description>
    ///     </item>
    ///     <item>
    ///         <description>The EventLogRecord ID matches PktMon's Frame Payload Event Id or PktMon's Frame Dropped Event Id.</description>
    ///     </item>
    /// </list>
    /// </summary>
    /// <param name="eventLogRecord">Any EventLogRecord.</param>
    /// <returns>If the provided etl event is PktMon's packet event returns true, otherwise false.</returns>
    private static bool IsValidPktMonPacket([NotNullWhen(true)] IEventLogRecordWrapper? eventLogRecord)
    {
        if (eventLogRecord is null ||
                            eventLogRecord.ProviderId != PktMonConstants.PktMonProviderGuid ||
                            (eventLogRecord.Id != PktMonConstants.PktMonEvtFramePayloadId &&
                             eventLogRecord.Id != PktMonConstants.PktMonEvtFrameDropPayloadId))
        {
            return false;
        }

        if (eventLogRecord.Id == PktMonConstants.PktMonEvtFrameDropPayloadId)
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Converts EventLogRecord to CapturedPacket.
    /// </summary>
    /// <param name="eventLogRecord">Valid EventLogRecord event.</param>
    /// <returns>A CapturedPacket representation of an etl event. In the case the event does not contain necessary parameters, the methods returns null.</returns>
    private static CapturedPacket? ParseEventLogRecord(IEventLogRecordWrapper eventLogRecord)
    {
        var timeCaptured = eventLogRecord.TimeCreated ?? MinEpochTime;

        var values = eventLogRecord.GetPropertyValues(PktMonConstants.PktMonEvtPropertySelector);
        if (values.Count != PktMonConstants.PktMonPropertyXPathQuery.Length)
        {
            return null;
        }

        if (values[0] is not ushort originalPayloadSize ||
            values[1] is not byte[] payload)
        {
            return null;
        }

        return new CapturedPacket(payload, originalPayloadSize, timeCaptured);
    }
}
