// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

namespace Microsoft.PacketCapture.Converter.Etl.Reader;

/// <summary>
/// Wrapper for <see cref="EventLogReader"/>.
///
/// This allows to use <see cref="EventLogReader"/> as <see cref="IEventLogReader"/> to make
/// mocking of <see cref="EventLogReader"/> possible. Otherwise, EventLogReader depends on an input file, which
/// makes it hard to mock.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="EventLogReaderWrapper"/> class.
/// </remarks>
/// <param name="reader">An instance of <see cref="EventLogReader"/>.</param>
[SupportedOSPlatform("windows")]
public class EventLogReaderWrapper(EventLogReader reader) : IEventLogReaderWrapper
{
    private readonly EventLogReader _reader = reader ?? throw new ArgumentNullException(nameof(reader));

    /// <inheritdoc />
    public void Dispose()
    {
        _reader.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Reads the next event in the file.
    /// </summary>
    /// <returns>Return EventLogRecord if another event is present, otherwise returns null. Any subsequent calls
    /// throw <see cref="InvalidOperationException"/>.
    /// </returns>
    /// <exception cref="InvalidCastException">If cast failed.</exception>
    public IEventLogRecordWrapper? ReadEvent()
    {
        var record = _reader.ReadEvent();

        if (record is EventLogRecord eventLogRecord)
        {
            return new EventLogRecordWrapper(eventLogRecord);
        }

        return null;
    }
}
