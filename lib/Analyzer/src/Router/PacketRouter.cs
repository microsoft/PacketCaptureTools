// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.


using Microsoft.Extensions.Logging;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Middleware.Application;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Router;

/// <summary>
/// Packet router.
/// </summary>
internal class PacketRouter
{
    private readonly ILogger? _logger;
    private readonly IEnumerable<ITransportLayerConnectionMiddleware> _transportLayerConnectionMiddlewares;
    private readonly IEnumerable<IApplicationConnectionMiddleware> _applicationConnectionMiddlewares;
    private readonly IEnumerable<IPacketAnalysis> _packetAnalyses;
    private readonly IEnumerable<ITransportLayerConnectionAnalysis> _transportLayerPacketAnalyses;
    private readonly IEnumerable<IApplicationLayerConnectionAnalysis> _applicationLayerConnectionAnalyses;

    /// <summary>
    /// Initializes a new instance of the <see cref="PacketRouter" /> class.
    /// </summary>
    /// <param name="configuration">The analysis configuration.</param>
    public PacketRouter(IAnalysisConfiguration configuration)
    {
        _ = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _logger = configuration.LoggerFactory?.CreateLogger<PacketRouter>();

        _transportLayerConnectionMiddlewares = configuration.TransportLayerConnectionMiddlewares?.ToList() ?? [];
        _applicationConnectionMiddlewares = configuration.ApplicationConnectionMiddlewares?.ToList() ?? [];

        _packetAnalyses = configuration.PacketAnalyses?.ToList() ?? [];
        _transportLayerPacketAnalyses = configuration.TransportLayerAnalyses?.ToList() ?? [];
        _applicationLayerConnectionAnalyses = configuration.ApplicationLayerAnalyses?.ToList() ?? [];
    }

    /// <summary>
    /// Routes the packet to the correct middleware and analyses.
    /// </summary>
    /// <param name="packet">The captured packet.</param>
    public void RoutePacket(CapturedPacket packet)
    {
        ProcessPacketAnalyses(packet);
        ProcessTransportLayerMiddlewares(packet);
    }

    private void ProcessPacketAnalyses(CapturedPacket packet)
    {
        foreach (var analysis in _packetAnalyses)
        {
            try
            {
                analysis.Process(packet);
            }
            catch (Exception exception)
            {
                _logger?.LogError(exception, "Error while executing packet analysis");
            }
        }
    }

    private void ProcessTransportLayerMiddlewares(CapturedPacket packet)
    {
        foreach (var transportConnectionMiddleware in _transportLayerConnectionMiddlewares)
        {
            TransportConnectionSnapshot? transportConnectionSnapshot = null;

            try
            {
                transportConnectionSnapshot = transportConnectionMiddleware.ProcessPacket(packet);
            }
            catch (Exception exception)
            {
                _logger?.LogError(exception, "Error while executing transport layer middleware");
            }

            if (transportConnectionSnapshot != null)
            {
                ProcessTransportLayerConnectionAnalyses(packet, transportConnectionSnapshot);

                if (transportConnectionSnapshot is TcpConnectionSnapshot tcpConnectionSnapshot &&
                    tcpConnectionSnapshot.TcpConnectionState != TcpConnectionState.Unknown)
                {
                    ProcessApplicationLayerMiddlewares(packet, tcpConnectionSnapshot);
                }
            }
        }
    }

    private void ProcessTransportLayerConnectionAnalyses(CapturedPacket packet, TransportConnectionSnapshot transportConnectionSnapshot)
    {
        foreach (var analysis in _transportLayerPacketAnalyses)
        {
            try
            {
                analysis.Process(packet, transportConnectionSnapshot);
            }
            catch (Exception exception)
            {
                _logger?.LogError(exception, "Error while executing transport layer analysis");
            }
        }
    }

    private void ProcessApplicationLayerMiddlewares(CapturedPacket packet, TransportConnectionSnapshot transportConnectionSnapshot)
    {
        foreach (var applicationConnectionMiddleware in _applicationConnectionMiddlewares)
        {
            ApplicationConnectionSnapshot? applicationConnectionSnapshot = null;

            try
            {
                applicationConnectionSnapshot = applicationConnectionMiddleware.Process(packet, transportConnectionSnapshot);
            }
            catch (Exception exception)
            {
                _logger?.LogError(exception, "Error while executing application layer middleware");
            }

            if (applicationConnectionSnapshot != null)
            {
                ProcessApplicationLayerConnectionAnalyses(packet, applicationConnectionSnapshot);
            }
        }
    }

    private void ProcessApplicationLayerConnectionAnalyses(CapturedPacket packet, ApplicationConnectionSnapshot applicationConnectionSnapshot)
    {
        foreach (var applicationLayerConnectionAnalysis in _applicationLayerConnectionAnalyses)
        {
            try
            {
                applicationLayerConnectionAnalysis.Process(packet, applicationConnectionSnapshot);
            }
            catch (Exception exception)
            {
                _logger?.LogError(exception, "Error while executing application layer analysis");
            }
        }
    }
}
