// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tds;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tds;

public class TdsFailedConnectionLatencyTableSectionTests
{
    private const string HeaderTitle = "TDS Failed Connection Latency";

    private const string HeaderDescription =
        @"TDS State Legend:
    TS=TcpSynSent, TH=TcpHandshake, PL=PreLogin, PR=PreLoginResponse, CH=ClientHello, SH=ServerHello, 
    KE=KeyExchange, CE=CipherChange, LM=LoginMessage, LA=LoginAck, LS=LastSuccessful, FA=Failure";

    private const string NoDataMessage = "TDS Failed Connection Latency table cannot be created - captured packets didn't contain any failed TDS connections.";

    private const string SourceIpAddress = "192.168.1.1";
    private const int SourcePort = 1234;
    private const int DestinationPort = 1433;

    private const string DestinationIpAddress1 = "192.168.0.1";
    private const string DestinationIpAddress2 = "192.168.0.2";
    private readonly TdsFailedConnectionLatencyTableSection _sut;

    private readonly TextRenderer _textRenderer;
    private readonly Dictionary<TransportLayerConnection, List<TdsConnectionLatencyAnalysisMetrics>> _tdsConnectionLatencyAnalysisMetrics;

    private readonly TransportLayerConnection _transportLayerConnection1;
    private readonly TransportLayerConnection _transportLayerConnection2;

    public TdsFailedConnectionLatencyTableSectionTests()
    {
        _textRenderer = new TextRenderer();
        _tdsConnectionLatencyAnalysisMetrics = [];

        _transportLayerConnection1 = new TransportLayerConnection(
            sourceIpAddress: IPAddress.Parse(SourceIpAddress),
            destinationIpAddress: IPAddress.Parse(DestinationIpAddress1),
            sourcePort: SourcePort,
            destinationPort: DestinationPort);

        _transportLayerConnection2 = new TransportLayerConnection(
            sourceIpAddress: IPAddress.Parse(SourceIpAddress),
            destinationIpAddress: IPAddress.Parse(DestinationIpAddress2),
            sourcePort: SourcePort,
            destinationPort: DestinationPort);

        var tdsConnectionLatencyAnalysis = new TdsConnectionLatencyAnalysis(tdsConnectionLatencyAnalysisMetrics: _tdsConnectionLatencyAnalysisMetrics);

        _sut = new TdsFailedConnectionLatencyTableSection(tdsConnectionLatencyAnalysis);
    }

    [Fact]
    public void Constructor_InvalidParameters_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "tdsConnectionLatencyAnalysis";

        // Act
        Func<TdsAverageLoginLatencyGraphSection> function = () => new TdsAverageLoginLatencyGraphSection((TdsConnectionLatencyAnalysis)null!);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }

    [Fact]
    public void Render_TextRendererNoData_RendersNoDataMessage()
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
    public void Render_TextRenderer_RendersTcpRetransmitsTable()
    {
        // Arrange
        _tdsConnectionLatencyAnalysisMetrics.AddToList(
            _transportLayerConnection1,
            new TdsConnectionLatencyAnalysisMetrics(
                tdsConnectionLatencies: new TdsConnectionLatencies(
                    lastSuccessfulTdsConnectionState: TdsConnectionState.PreLogin,
                    tcpHandshakeToPreLoginLatency: TimeSpan.FromMilliseconds(50),
                    lastSuccessfulToLastStateLatency: TimeSpan.FromMilliseconds(100),
                    preLoginToLatestStateLatency: TimeSpan.FromMilliseconds(100),
                    totalLatency: TimeSpan.FromSeconds(0.15))));

        _tdsConnectionLatencyAnalysisMetrics.AddToList(
            _transportLayerConnection1,
            new TdsConnectionLatencyAnalysisMetrics(
                tdsConnectionLatencies: new TdsConnectionLatencies(
                    lastSuccessfulTdsConnectionState: TdsConnectionState.PreLoginResponse,
                    tcpHandshakeToPreLoginLatency: TimeSpan.FromMilliseconds(50),
                    preLoginToPreLoginResponseLatency: TimeSpan.FromMilliseconds(125),
                    lastSuccessfulToLastStateLatency: TimeSpan.FromMilliseconds(100),
                    preLoginToLatestStateLatency: TimeSpan.FromMilliseconds(225),
                    totalLatency: TimeSpan.FromSeconds(0.27))));

        _tdsConnectionLatencyAnalysisMetrics.AddToList(
            _transportLayerConnection1,
            new TdsConnectionLatencyAnalysisMetrics(
                tdsConnectionLatencies: new TdsConnectionLatencies(
                    lastSuccessfulTdsConnectionState: TdsConnectionState.ClientHello,
                    tcpHandshakeToPreLoginLatency: TimeSpan.FromMilliseconds(50),
                    preLoginToPreLoginResponseLatency: TimeSpan.FromMilliseconds(125),
                    preLoginResponseToClientHelloLatency: TimeSpan.FromMilliseconds(75),
                    lastSuccessfulToLastStateLatency: TimeSpan.FromMilliseconds(100),
                    preLoginToLatestStateLatency: TimeSpan.FromMilliseconds(300),
                    totalLatency: TimeSpan.FromSeconds(0.35))));


        _tdsConnectionLatencyAnalysisMetrics.AddToList(
            _transportLayerConnection1,
            new TdsConnectionLatencyAnalysisMetrics(
                tdsConnectionLatencies: new TdsConnectionLatencies(
                    lastSuccessfulTdsConnectionState: TdsConnectionState.ServerHello,
                    tcpHandshakeToPreLoginLatency: TimeSpan.FromMilliseconds(50),
                    preLoginToPreLoginResponseLatency: TimeSpan.FromMilliseconds(100),
                    preLoginResponseToClientHelloLatency: TimeSpan.FromMilliseconds(125),
                    clientHelloToServerHelloLatency: TimeSpan.FromMilliseconds(150),
                    lastSuccessfulToLastStateLatency: TimeSpan.FromMilliseconds(100),
                    preLoginToLatestStateLatency: TimeSpan.FromMilliseconds(475),
                    totalLatency: TimeSpan.FromSeconds(0.52))));

        _tdsConnectionLatencyAnalysisMetrics.AddToList(
            _transportLayerConnection2,
            new TdsConnectionLatencyAnalysisMetrics(
                tdsConnectionLatencies: new TdsConnectionLatencies(
                    lastSuccessfulTdsConnectionState: TdsConnectionState.KeyExchange,
                    tcpHandshakeToPreLoginLatency: TimeSpan.FromMilliseconds(50),
                    preLoginToPreLoginResponseLatency: TimeSpan.FromMilliseconds(100),
                    preLoginResponseToClientHelloLatency: TimeSpan.FromMilliseconds(125),
                    clientHelloToServerHelloLatency: TimeSpan.FromMilliseconds(150),
                    serverHelloToKeyExchangeLatency: TimeSpan.FromMilliseconds(75),
                    lastSuccessfulToLastStateLatency: TimeSpan.FromMilliseconds(100),
                    preLoginToLatestStateLatency: TimeSpan.FromMilliseconds(550),
                    totalLatency: TimeSpan.FromSeconds(0.60))));

        _tdsConnectionLatencyAnalysisMetrics.AddToList(
            _transportLayerConnection2,
            new TdsConnectionLatencyAnalysisMetrics(
                tdsConnectionLatencies: new TdsConnectionLatencies(
                    lastSuccessfulTdsConnectionState: TdsConnectionState.CipherChange,
                    tcpHandshakeToPreLoginLatency: TimeSpan.FromMinutes(120),
                    preLoginToPreLoginResponseLatency: TimeSpan.FromMilliseconds(5478),
                    preLoginResponseToClientHelloLatency: TimeSpan.FromMilliseconds(12345),
                    clientHelloToServerHelloLatency: TimeSpan.FromSeconds(150),
                    serverHelloToKeyExchangeLatency: TimeSpan.FromSeconds(664),
                    keyExchangeToCipherChangeLatency: TimeSpan.FromMinutes(50),
                    lastSuccessfulToLastStateLatency: TimeSpan.FromMinutes(61),
                    preLoginToLatestStateLatency: TimeSpan.FromMinutes(120),
                    totalLatency: TimeSpan.FromHours(2))));

        _tdsConnectionLatencyAnalysisMetrics.AddToList(
            _transportLayerConnection2,
            new TdsConnectionLatencyAnalysisMetrics(
                tdsConnectionLatencies: new TdsConnectionLatencies(
                    lastSuccessfulTdsConnectionState: TdsConnectionState.LoginMessage,
                    tcpHandshakeToPreLoginLatency: TimeSpan.FromMilliseconds(50),
                    preLoginToPreLoginResponseLatency: TimeSpan.FromMilliseconds(100),
                    preLoginResponseToClientHelloLatency: TimeSpan.FromMilliseconds(125),
                    clientHelloToServerHelloLatency: TimeSpan.FromMilliseconds(150),
                    serverHelloToKeyExchangeLatency: TimeSpan.FromMilliseconds(75),
                    keyExchangeToCipherChangeLatency: TimeSpan.FromMilliseconds(50),
                    cipherChangeToLoginMessageLatency: TimeSpan.FromMilliseconds(175),
                    lastSuccessfulToLastStateLatency: TimeSpan.FromMilliseconds(200),
                    preLoginToLatestStateLatency: TimeSpan.FromMilliseconds(875),
                    totalLatency: TimeSpan.FromSeconds(0.92))));

        var expectedResult =
            $@"[{HeaderTitle}]
{HeaderDescription}

+------------------+------------------+-----------------+-------+--------+--------+--------+--------+-------+--------+--------+--------+--------+
| Source           | Destination      | Last successful | TH-PL | PL-PR  | PR-CH  | CH-SH  | SH-KE  | KE-CE | CE-LM  | LS-FA  | PL-FA  | TS-FA  |
+------------------+------------------+-----------------+-------+--------+--------+--------+--------+-------+--------+--------+--------+--------+
| 192.168.1.1:1234 | 192.168.0.1:1433 | PL              | 50 ms | _      | _      | _      | _      | _     | _      | 100 ms | 100 ms | 150 ms |
| 192.168.1.1:1234 | 192.168.0.1:1433 | PR              | 50 ms | 125 ms | _      | _      | _      | _     | _      | 100 ms | 225 ms | 270 ms |
| 192.168.1.1:1234 | 192.168.0.1:1433 | CH              | 50 ms | 125 ms | 75 ms  | _      | _      | _     | _      | 100 ms | 300 ms | 350 ms |
| 192.168.1.1:1234 | 192.168.0.1:1433 | SH              | 50 ms | 100 ms | 125 ms | 150 ms | _      | _     | _      | 100 ms | 475 ms | 520 ms |
| 192.168.1.1:1234 | 192.168.0.2:1433 | KE              | 50 ms | 100 ms | 125 ms | 150 ms | 75 ms  | _     | _      | 100 ms | 550 ms | 600 ms |
| 192.168.1.1:1234 | 192.168.0.2:1433 | CE              | 2 h   | 5.47 s | 12.3 s | 2m 30s | 11m 4s | 50 m  | _      | 1h 1m  | 2 h    | 2 h    |
| 192.168.1.1:1234 | 192.168.0.2:1433 | LM              | 50 ms | 100 ms | 125 ms | 150 ms | 75 ms  | 50 ms | 175 ms | 200 ms | 875 ms | 920 ms |
+------------------+------------------+-----------------+-------+--------+--------+--------+--------+-------+--------+--------+--------+--------+

";

        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }
}