// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tds;
using Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tds.Fixtures;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tds;

public class TdsLoginConnectionAnalysesTableSectionTests
{
    private const string SourceIpAddress = "127.0.0.1";
    private const int SourcePort = 80;

    private const string DestinationIpAddress = "127.0.0.2";
    private const int DestinationPort = 1433;

    private const string TableHeaderTitle = "TDS Login Connection Analyses";

    private const string TableHeaderDescription = "A table showing the total successful TDS connections, and how many failures occurred at each step in the login process for each connection.";

    private const string NoDataMessage = "TDS Login Connection Analyses table cannot be created - captured packets didn't contain any TDS login connections.";
    private readonly TdsLoginConnectionAnalysesTableSection _sut;

    private readonly TextRenderer _textRenderer;
    private readonly TdsLoginConnectionAnalysisFixture _tdsLoginConnectionAnalysisFixture;
    private readonly Dictionary<TransportLayerConnection, List<TdsLoginConnectionMetrics>> _connectionStates;

    private readonly TransportLayerConnection _transportLayerConnection;

    public TdsLoginConnectionAnalysesTableSectionTests()
    {
        _textRenderer = new TextRenderer();
        _connectionStates = [];

        _transportLayerConnection = new TransportLayerConnection(
            sourceIpAddress: IPAddress.Parse(SourceIpAddress),
            destinationIpAddress: IPAddress.Parse(DestinationIpAddress),
            sourcePort: SourcePort,
            destinationPort: DestinationPort);

        _tdsLoginConnectionAnalysisFixture = new TdsLoginConnectionAnalysisFixture(_transportLayerConnection);

        var tdsLoginConnectionAnalysis = new TdsLoginConnectionAnalysis(_connectionStates);
        _sut = new TdsLoginConnectionAnalysesTableSection(tdsLoginConnectionAnalysis);
    }

    [Fact]
    public void Constructor_InvalidParams_ThrowsException()
    {
        // Arrange
        var argumentName = "tdsLoginConnectionAnalysis";

        // Act
        Func<TdsLoginConnectionAnalysesTableSection> function = () => new TdsLoginConnectionAnalysesTableSection((TdsLoginConnectionAnalysis)null!);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }

    [Fact]
    public void Render_NoFailedConnections_ShowsMessage()
    {
        // Arrange
        var expectedResult =
            $@"{NoDataMessage}

";
        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }

    [Fact]
    public void Render_ManyFailedConnections_ShowsConnections()
    {
        // Arrange
        var timestamp = DateTime.UtcNow;

        var tdsLoginConnectionMetrics = new List<TdsLoginConnectionMetrics>
        {
            _tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.ClientHello, timestamp, TimeSpan.FromSeconds(3)),
            _tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.ClientHello, timestamp, TimeSpan.FromSeconds(3)),
            _tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.ClientHello, timestamp.AddSeconds(1), TimeSpan.FromSeconds(2)),
            _tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.CipherChange, timestamp.AddSeconds(1), TimeSpan.FromSeconds(2)),
            _tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.ClientHello, timestamp.AddSeconds(1), TimeSpan.FromSeconds(2)),
            _tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.ServerHello, timestamp.AddSeconds(2), TimeSpan.FromSeconds(1)),
            _tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.LoginAck, timestamp.AddSeconds(3), TimeSpan.FromSeconds(1)),
        };

        _connectionStates.Add(_tdsLoginConnectionAnalysisFixture.GetTransportLayerConnection(), tdsLoginConnectionMetrics);


        var expectedResult =
            $@"[{TableHeaderTitle}]
{TableHeaderDescription}

+------------------------+---------------------+----+----+----+----+----+----+----+----+
| Connection             | % Successful Logins | TH | PL | PR | CH | SH | KE | CE | LM |
+------------------------+---------------------+----+----+----+----+----+----+----+----+
| 127.0.0.1 -> 127.0.0.2 | 14.28572% (1/7)     | 0  | 0  | 0  | 4  | 1  | 0  | 1  | 0  |
+------------------------+---------------------+----+----+----+----+----+----+----+----+

";
        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }
}