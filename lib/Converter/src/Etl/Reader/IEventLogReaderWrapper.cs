// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Microsoft.PacketCapture.Converter.Etl.Reader;

/// <summary>
/// Reader that can read <see cref="IEventLogRecord"/> events.
/// </summary>
public interface IEventLogReaderWrapper : IDisposable
{
    /// <summary>
    /// Reads the next event in the file.
    /// </summary>
    /// <returns>Return EventRecord if another event is present, otherwise returns null. Any subsequent calls
    /// throw <see cref="InvalidOperationException"/>.
    /// </returns>
    IEventLogRecordWrapper? ReadEvent();
}
