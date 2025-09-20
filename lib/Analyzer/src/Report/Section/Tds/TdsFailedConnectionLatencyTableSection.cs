// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Tds;

/// <summary>
/// TDS failed logins over time represented as a graph.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TdsFailedConnectionLatencyTableSection" /> class.
/// </remarks>
/// <param name="tdsConnectionLatencyAnalysis">The TDS connection latency analysis.</param>
/// <exception cref="ArgumentNullException">TDS connection latency analysis cannot be null.</exception>
public class TdsFailedConnectionLatencyTableSection(TdsConnectionLatencyAnalysis tdsConnectionLatencyAnalysis) : TableSection
{
    private const string LatencyNotAvailable = "_";
    private readonly TdsConnectionLatencyAnalysis _tdsConnectionLatencyAnalysis = tdsConnectionLatencyAnalysis ?? throw new ArgumentNullException(nameof(tdsConnectionLatencyAnalysis));

    public TdsFailedConnectionLatencyTableSection(IAnalysisProvider analysisProvider)
        : this(analysisProvider.GetRequiredApplicationLayerConnectionAnalysis<TdsConnectionLatencyAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string TableHeaderTitle => "TDS Failed Connection Latency";

    /// <inheritdoc />
    protected override string TableHeaderDescription =>
        @"TDS State Legend:
    TS=TcpSynSent, TH=TcpHandshake, PL=PreLogin, PR=PreLoginResponse, CH=ClientHello, SH=ServerHello, 
    KE=KeyExchange, CE=CipherChange, LM=LoginMessage, LA=LoginAck, LS=LastSuccessful, FA=Failure";

    /// <inheritdoc />
    protected override string NoDataMessage => $"{TableHeaderTitle} table cannot be created - captured packets didn't contain any failed TDS connections.";

    /// <inheritdoc />
    protected override string[] TableHeaders =>
    [
        "Source",
        "Destination",
        "Last successful",
        "TH-PL",
        "PL-PR",
        "PR-CH",
        "CH-SH",
        "SH-KE",
        "KE-CE",
        "CE-LM",
        "LS-FA",
        "PL-FA",
        "TS-FA",
    ];

    /// <inheritdoc />
    protected override List<string[]> GetTableData()
    {
        return [.. _tdsConnectionLatencyAnalysis.FailedTdsConnectionMetrics
            .OrderBy(m => $"{m.Key.SourceIpAddress},{m.Key.DestinationIpAddress}")
            .SelectMany(l => l.Value.Select(m => ToTableRow(l.Key, m)))];
    }

    private static string[] ToTableRow(TransportLayerConnection transportLayerConnection, TdsConnectionLatencies tdsConnectionLatencies)
    {
        return
        [
            $"{transportLayerConnection.SourceIpAddress}:{transportLayerConnection.SourcePort}",
            $"{transportLayerConnection.DestinationIpAddress}:{transportLayerConnection.DestinationPort}",
            tdsConnectionLatencies.LastSuccessfulTdsConnectionState.GetTwoLetterAbbreviation(),
            tdsConnectionLatencies.TcpHandshakeToPreLoginLatency.ToReadableFormat() ?? LatencyNotAvailable,
            tdsConnectionLatencies.PreLoginToPreLoginResponseLatency.ToReadableFormat() ?? LatencyNotAvailable,
            tdsConnectionLatencies.PreLoginResponseToClientHelloLatency.ToReadableFormat() ?? LatencyNotAvailable,
            tdsConnectionLatencies.ClientHelloToServerHelloLatency.ToReadableFormat() ?? LatencyNotAvailable,
            tdsConnectionLatencies.ServerHelloToKeyExchangeLatency.ToReadableFormat() ?? LatencyNotAvailable,
            tdsConnectionLatencies.KeyExchangeToCipherChangeLatency.ToReadableFormat() ?? LatencyNotAvailable,
            tdsConnectionLatencies.CipherChangeToLoginMessageLatency.ToReadableFormat() ?? LatencyNotAvailable,
            tdsConnectionLatencies.LastSuccessfulToLastStateLatency.ToReadableFormat() ?? LatencyNotAvailable,
            tdsConnectionLatencies.PreLoginToLatestStateLatency.ToReadableFormat() ?? LatencyNotAvailable,
            tdsConnectionLatencies.TotalLatency.ToReadableFormat() ?? LatencyNotAvailable,
        ];
    }
}
