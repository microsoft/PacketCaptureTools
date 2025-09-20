// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Reader;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace Microsoft.PacketCapture.Analyzer.Controller;

/// <summary>
/// A controller entry point for the packet capture analysis library.
/// </summary>
public sealed class AnalysisController : BaseController
{
    private const int FileBufferReadSize = 128 * 1024; // 128kB

    private readonly ILogger? _logger;
    private readonly IEnumerator<IReader> _readerEnumerator;

    /// <summary>
    /// Initializes a new instance of the <see cref="AnalysisController" /> class.
    /// </summary>
    /// <param name="configuration">The analysis configuration.</param>
    /// <param name="filePaths">The paths to the packet capture files. Analysis of the files will be done in the same sequence as provided.</param>
    public AnalysisController(IAnalysisConfiguration configuration, params string[] filePaths)
        : this(configuration, filePaths as IEnumerable<string>)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AnalysisController" /> class.
    /// </summary>
    /// <param name="configuration">The analysis configuration.</param>
    /// <param name="filePaths">The paths to the packet capture files. Analysis of the files will be done in the same sequence as provided.</param>
    public AnalysisController(IAnalysisConfiguration configuration, IEnumerable<string> filePaths)
        : this(configuration, filePaths.Select(filePath => new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: FileBufferReadSize)))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AnalysisController" /> class.
    /// </summary>
    /// <param name="configuration">The analysis configuration.</param>
    /// <param name="streams">The streams containing capture packet data. Analysis of the streams will be done in the same sequence as provided.</param>
    public AnalysisController(IAnalysisConfiguration configuration, params Stream[] streams)
        : this(configuration, streams as IEnumerable<Stream>)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AnalysisController" /> class.
    /// </summary>
    /// <param name="configuration">The analysis configuration.</param>
    /// <param name="streams">The streams containing capture packet data. Analysis of the streams will be done in the same sequence as provided.</param>
    public AnalysisController(IAnalysisConfiguration configuration, IEnumerable<Stream> streams)
        : this(configuration, streams.Select(stream => new PcapNgReader(stream, configuration)))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AnalysisController" /> class.
    /// </summary>
    /// <param name="configuration">The analysis configuration.</param>
    /// <param name="readers">The readers able to read packets.</param>
    internal AnalysisController(IAnalysisConfiguration configuration, IEnumerable<IReader> readers)
        : base(configuration)
    {
        _ = readers ?? throw new ArgumentNullException(nameof(readers));
        _logger = configuration.LoggerFactory?.CreateLogger<AnalysisController>();
        _readerEnumerator = readers.GetEnumerator();
    }

    /// <inheritdoc />
    public override void Execute(CancellationToken cancellationToken = default)
    {
        var startTime = DateTime.UtcNow;
        var sources = 0;
        var packets = 0;

        while (_readerEnumerator.MoveNext())
        {
            using var reader = _readerEnumerator.Current;
            sources++;

            while (reader.HasNext())
            {
                var capturedPacket = reader.ReadNext();
                if (capturedPacket is not null)
                {
                    PacketRouter.RoutePacket(capturedPacket);
                    packets++;
                }

                cancellationToken.ThrowIfCancellationRequested();
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        _logger?.LogInformation("Analysis completed, processed {ProcessedPacketCount} packet(s) from {SourceCount} source(s), total duration: {TotalDuration}", packets, sources, (DateTime.UtcNow - startTime).ToString("d\\.hh\\:mm\\:ss\\.fff"));
    }

    /// <inheritdoc />
    public override void Dispose()
    {
        while (_readerEnumerator.MoveNext())
        {
            _readerEnumerator.Current?.Dispose();
        }

        _readerEnumerator.Dispose();
    }
}