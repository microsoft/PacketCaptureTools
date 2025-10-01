// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Converter.Packet;
using System;
using System.Diagnostics.Eventing.Reader;

namespace Microsoft.PacketCapture.Converter.Etl.Reader;

/// <summary>
/// ETL packet reader that reads events from a <see cref="IEventLogReader"/> and converts them to <see cref="CapturedPacket"/> with a <see cref="ICapturedPacketAdapter{IEventLogRecordWrapper}"/>.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="EtlPacketReader"/> class.
/// </remarks>
/// <param name="reader">EventLogReader wrapper.</param>
/// <param name="adapter">Adapter for converting <see cref="EventLogRecord"/> to <see cref="CapturedPacket"/>.</param>
/// <exception cref="ArgumentNullException">Throws a null exception if any of the parameters are null.</exception>
public class EtlPacketReader(IEventLogReaderWrapper reader, ICapturedPacketAdapter<IEventLogRecordWrapper> adapter) : IPacketReader
{
    private readonly IEventLogReaderWrapper _reader = reader ?? throw new ArgumentNullException(nameof(reader));
    private readonly ICapturedPacketAdapter<IEventLogRecordWrapper> _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
    private CapturedPacket? _cachedPacket;
    private bool _endOfSourceReached;

    /// <inheritdoc />
    public bool HasNext()
    {
        if (_cachedPacket != null)
        {
            return true;
        }

        if (_endOfSourceReached)
        {
            return false;
        }

        _cachedPacket = ReadNext();

        return _cachedPacket != null;
    }

    /// <inheritdoc />
    public virtual CapturedPacket? ReadNext()
    {
        if (_cachedPacket != null)
        {
            try
            {
                return _cachedPacket;
            }
            finally
            {
                _cachedPacket = null;
            }
        }

        if (_cachedPacket != null)
        {
            var capturedPacket = _cachedPacket;
            _cachedPacket = null;
            return capturedPacket;
        }

        if (_endOfSourceReached)
        {
            return null;
        }

        while (true)
        {
            var eventLogRecord = _reader.ReadEvent();
            if (eventLogRecord == null)
            {
                _endOfSourceReached = true;
                return null;
            }

            var capturedPacket = _adapter.Convert(eventLogRecord);
            if (capturedPacket != null)
            {
                return capturedPacket;
            }
        }
    }

    /// <summary>
    /// Disposes of unmanaged resources by <see cref="EventLogReader"/>.
    /// </summary>
    public void Dispose()
    {
        _reader.Dispose();
        GC.SuppressFinalize(this);
    }
}
