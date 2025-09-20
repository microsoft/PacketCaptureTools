// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Middleware.Application;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Report;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Controller.Configuration;

/// <summary>
/// Analysis configuration.
/// </summary>
public class AnalysisConfiguration : IAnalysisConfiguration
{
    /// <summary>
    /// Gets or sets the factory used to create logger instances for the application.
    /// </summary>
    public ILoggerFactory? LoggerFactory { get; init; }

    /// <summary>
    /// Gets or sets the report.
    /// </summary>
    public required IReport Report { get; init; }

    /// <summary>
    /// Gets or sets the collection of packet analyses used for the report.
    /// </summary>
    public required IEnumerable<IPacketAnalysis> PacketAnalyses { get; init; }

    /// <summary>
    /// Gets or sets the collection of transport layer analyses used for the report.
    /// </summary>
    public required IEnumerable<ITransportLayerConnectionAnalysis> TransportLayerAnalyses { get; init; }

    /// <summary>
    /// Gets or sets the collection of application layer analyses used for the report.
    /// </summary>
    public required IEnumerable<IApplicationLayerConnectionAnalysis> ApplicationLayerAnalyses { get; init; }

    /// <summary>
    /// Gets or sets the transport layer connection middlewares.
    /// </summary>
    public required IEnumerable<ITransportLayerConnectionMiddleware> TransportLayerConnectionMiddlewares { get; init; }

    /// <summary>
    /// Gets or sets the application layer connection middlewares.
    /// </summary>
    public required IEnumerable<IApplicationConnectionMiddleware> ApplicationConnectionMiddlewares { get; init; }
}
