// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Tds;

/// <summary>
/// TDS protocol login connection analyses table section.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TdsLoginConnectionAnalysesTableSection" /> class.
/// </remarks>
/// <param name="tdsLoginConnectionAnalysis">TDS login connection analysis.</param>
public class TdsLoginConnectionAnalysesTableSection(TdsLoginConnectionAnalysis tdsLoginConnectionAnalysis) : TableSection
{
    private readonly TdsLoginConnectionAnalysis _tdsLoginConnectionAnalysis = tdsLoginConnectionAnalysis ?? throw new ArgumentNullException(nameof(tdsLoginConnectionAnalysis));

    public TdsLoginConnectionAnalysesTableSection(IAnalysisProvider analysisProvider)
        : this(analysisProvider.GetRequiredApplicationLayerConnectionAnalysis<TdsLoginConnectionAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string TableHeaderTitle => "TDS Login Connection Analyses";

    /// <inheritdoc />
    protected override string TableHeaderDescription => "A table showing the total successful TDS connections, and how many failures occurred at each step in the login process for each connection.";

    /// <inheritdoc />
    protected override string NoDataMessage => $"{TableHeaderTitle} table cannot be created - captured packets didn't contain any TDS login connections.";

    /// <inheritdoc />
    protected override string[] TableHeaders =>
        [
            "Connection",
            "% Successful Logins",
            "TH",
            "PL",
            "PR",
            "CH",
            "SH",
            "KE",
            "CE",
            "LM",
        ];

    /// <inheritdoc />
    protected override List<string[]> GetTableData()
    {
        var successfulRows = new List<string[]>();
        var successfulConnections = _tdsLoginConnectionAnalysis.GetSuccessfulConnectionsByNetworkConnection();

        foreach (var connection in successfulConnections)
        {
            var key = $"{connection.Key.SourceIpAddress} -> {connection.Key.DestinationIpAddress}";
            var totalConnections = 0;

            foreach (var connectionState in _tdsLoginConnectionAnalysis.ConnectionStates)
            {
                totalConnections += connectionState.Value.Count(item => connectionState.Key.SourceIpAddress.Equals(connection.Key.SourceIpAddress));
            }

            var successPercentage = ((float)connection.Value / totalConnections) * 100;
            var failedLoginStates = _tdsLoginConnectionAnalysis.GetFailedConnectionStatesByConnection(connection.Key);
            successfulRows.Add(
                [
                    key,
                    $"{Math.Round(successPercentage, 5)}% ({connection.Value}/{totalConnections})",
                    $"{failedLoginStates[TdsConnectionState.TcpHandshake]}",
                    $"{failedLoginStates[TdsConnectionState.PreLogin]}",
                    $"{failedLoginStates[TdsConnectionState.PreLoginResponse]}",
                    $"{failedLoginStates[TdsConnectionState.ClientHello]}",
                    $"{failedLoginStates[TdsConnectionState.ServerHello]}",
                    $"{failedLoginStates[TdsConnectionState.KeyExchange]}",
                    $"{failedLoginStates[TdsConnectionState.CipherChange]}",
                    $"{failedLoginStates[TdsConnectionState.LoginMessage]}",
                ]);
        }

        return successfulRows;
    }
}
