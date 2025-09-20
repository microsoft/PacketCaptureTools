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
/// Analysis configuration interface.
/// </summary>
public interface IAnalysisConfiguration
{
    /// <summary>
    /// Gets the factory used to create logger instances for the application.
    /// </summary>
    ILoggerFactory? LoggerFactory { get; }

    /// <summary>
    /// Gets the report.
    /// </summary>
    IReport Report { get; }

    /// <summary>
    /// Gets the collection of packet analyses used for the report.
    /// </summary>
    IEnumerable<IPacketAnalysis> PacketAnalyses { get; }

    /// <summary>
    /// Gets the collection of transport layer analyses used for the report.
    /// </summary>
    IEnumerable<ITransportLayerConnectionAnalysis> TransportLayerAnalyses { get; }

    /// <summary>
    /// Gets the collection of application layer analyses used for the report.
    /// </summary>
    IEnumerable<IApplicationLayerConnectionAnalysis> ApplicationLayerAnalyses { get; }

    /// <summary>
    /// Gets the transport layer connection middlewares.
    /// </summary>
    IEnumerable<ITransportLayerConnectionMiddleware> TransportLayerConnectionMiddlewares { get; }

    /// <summary>
    /// Gets the application layer connection middlewares.
    /// </summary>
    IEnumerable<IApplicationConnectionMiddleware> ApplicationConnectionMiddlewares { get; }
}
