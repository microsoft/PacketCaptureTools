// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using System;
using System.Collections.Generic;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tds.Fixtures;

internal class TdsLoginConnectionAnalysisFixture
{
    private const string SourceIpAddress = "127.0.0.1";
    private const int SourcePort = 80;

    private const string DestinationIpAddress = "127.0.0.2";
    private const int DestinationPort = 1433;
    private readonly TransportLayerConnection _transportLayerConnection;

    public TdsLoginConnectionAnalysisFixture(TransportLayerConnection? transportLayerConnection = null)
    {
        _transportLayerConnection = transportLayerConnection ??
                                    new TransportLayerConnection(
                                        sourceIpAddress: IPAddress.Parse(SourceIpAddress),
                                        destinationIpAddress: IPAddress.Parse(DestinationIpAddress),
                                        sourcePort: SourcePort,
                                        destinationPort: DestinationPort);
    }

    internal TransportLayerConnection GetTransportLayerConnection()
    {
        return _transportLayerConnection;
    }

    internal Dictionary<TransportLayerConnection, List<TdsLoginConnectionMetrics>> GetConnectionState(
        TransportLayerConnection? transportLayerConnection = null,
        List<TdsLoginConnectionMetrics>? tdsLoginConnectionMetricsList = null,
        TdsConnectionState tdsConnectionState = TdsConnectionState.Unknown,
        DateTime firstCapturedTime = default,
        TimeSpan duration = default,
        int startFrameNumber = 1,
        int endFrameNumber = 16,
        int totalSeenPackets = 16)
    {
        return new Dictionary<TransportLayerConnection, List<TdsLoginConnectionMetrics>>
        {
            {
                transportLayerConnection ?? _transportLayerConnection,
                tdsLoginConnectionMetricsList ??
                new List<TdsLoginConnectionMetrics>
                {
                    GetTdsLoginConnectionMetrics(
                        startFrameNumber: startFrameNumber,
                        endFrameNumber: endFrameNumber,
                        totalSeenPackets: totalSeenPackets,
                        firstCapturedTime: firstCapturedTime,
                        tdsConnectionState: tdsConnectionState),
                }
            },
        };
    }

    internal TdsLoginConnectionMetrics GetTdsLoginConnectionMetrics(
        TdsConnectionState tdsConnectionState = TdsConnectionState.Unknown,
        DateTime firstCapturedTime = default,
        TimeSpan duration = default,
        int startFrameNumber = 1,
        int endFrameNumber = 16,
        int totalSeenPackets = 16)
    {
        return new TdsLoginConnectionMetrics(
            startFrameNumber: startFrameNumber,
            endFrameNumber: endFrameNumber,
            totalSeenPackets: totalSeenPackets,
            firstCapturedTime: firstCapturedTime,
            lastCapturedTime: firstCapturedTime.Add(duration),
            connectionState: tdsConnectionState,
            lastSuccessfulConnectionState: tdsConnectionState);
    }
}