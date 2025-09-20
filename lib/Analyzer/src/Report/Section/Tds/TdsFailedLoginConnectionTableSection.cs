// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Extensions;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Tds;

/// <summary>
/// TDS protocol failed login connection section.
/// </summary>
public class TdsFailedLoginConnectionTableSection : TableSection
{
    private readonly TdsLoginConnectionAnalysis _tdsLoginConnectionAnalysis;

    /// <summary>
    /// Initializes a new instance of the <see cref="TdsFailedLoginConnectionTableSection" /> class.
    /// </summary>
    /// <param name="tdsLoginConnectionAnalysis">TDS login connection analysis.</param>
    public TdsFailedLoginConnectionTableSection(TdsLoginConnectionAnalysis tdsLoginConnectionAnalysis)
    {
        _tdsLoginConnectionAnalysis = tdsLoginConnectionAnalysis ?? throw new ArgumentNullException(nameof(tdsLoginConnectionAnalysis));
    }

    public TdsFailedLoginConnectionTableSection(IAnalysisProvider analysisProvider)
        : this(analysisProvider.GetRequiredApplicationLayerConnectionAnalysis<TdsLoginConnectionAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string TableHeaderTitle => "TDS Failed Login Connections";

    /// <inheritdoc />
    protected override string TableHeaderDescription =>
        @"A table showing the total failed TDS connections, and how many steps in the login process were captured.

    TH=TcpHandshake, PL=PreLogin, PR=PreLoginResponse, CH=ClientHello, SH=ServerHello,
    KE=KeyExchange, CE=CipherChange, LM=LoginSent, LR=LoginResponse";

    /// <inheritdoc />
    protected override string NoDataMessage => $"{TableHeaderTitle} table cannot be created - captured packets didn't contain any TDS failed login connections.";

    /// <inheritdoc />
    protected override string[] TableHeaders =>
        new[]
        {
            "Frame No.",
            "Failed Connection",
            "Login steps",
            "Connection duration",
            "No. of Packets",
        };

    /// <inheritdoc />
    protected override List<string[]> GetTableData()
    {
        var failedRows = new List<string[]>();

        foreach (var connectionState in _tdsLoginConnectionAnalysis.ConnectionStates)
        {
            foreach (var tdsLoginConnectionMetric in connectionState.Value)
            {
                var key = $"{connectionState.Key.SourceIpAddress}:{connectionState.Key.SourcePort} -> {connectionState.Key.DestinationIpAddress}:{connectionState.Key.DestinationPort}";

                if (!tdsLoginConnectionMetric.ConnectionState.IsTdsConnectionFinishedWithSuccess())
                {
                    failedRows.Add(
                        new[]
                        {
                            $"{tdsLoginConnectionMetric.StartFrameNumber} -> {tdsLoginConnectionMetric.EndFrameNumber}",
                            key,
                            tdsLoginConnectionMetric.LastSuccessfulConnectionState.GetLoginStepsCompleted(),
                            tdsLoginConnectionMetric.ConnectionDuration.ToReadableFormat(),
                            tdsLoginConnectionMetric.TotalSeenPackets.ToString(),
                        });
                }
            }
        }

        return failedRows;
    }
}
