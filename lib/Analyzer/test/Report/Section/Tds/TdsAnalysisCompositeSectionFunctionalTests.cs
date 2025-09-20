// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tds;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tds.Fixtures;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tds;

public class TdsAnalysisCompositeSectionFunctionalTests
{
    private const string SourceIpAddress = "192.168.1.1";
    private const int SourcePort = 1234;
    private const int DestinationPort = 1433;

    private const string DestinationIpAddress1 = "192.168.0.1";
    private const string DestinationIpAddress2 = "192.168.0.2";
    private readonly TdsAnalysisCompositeSection _sut;

    private readonly TextRenderer _textRenderer;

    private readonly Dictionary<TransportLayerConnection, List<TdsConnectionLatencyAnalysisMetrics>> _tdsConnectionLatencyAnalysisMetrics;
    private readonly Dictionary<TransportLayerConnection, List<TdsLoginConnectionMetrics>> _tdsLoginConnectionMetrics;

    private readonly TransportLayerConnection _transportLayerConnection1;
    private readonly TransportLayerConnection _transportLayerConnection2;

    public TdsAnalysisCompositeSectionFunctionalTests()
    {
        _textRenderer = new TextRenderer();
        _tdsConnectionLatencyAnalysisMetrics = [];
        _tdsLoginConnectionMetrics = [];

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

        var tdsConnectionLatencyAnalysis = new TdsConnectionLatencyAnalysis(
            tdsConnectionLatencyAnalysisMetrics: _tdsConnectionLatencyAnalysisMetrics);

        var tdsLoginConnectionAnalysis = new TdsLoginConnectionAnalysis(_tdsLoginConnectionMetrics);

        var analysisContainer = new AnalysisContainer();

        analysisContainer.AddPacketAnalysis(AnalysisFixtureFactory.GetPacketCounterAnalysis());
        analysisContainer.AddPacketAnalysis(AnalysisFixtureFactory.GetThroughputAnalysis());
        analysisContainer.AddPacketAnalysis(AnalysisFixtureFactory.GetTcpPacketResetAnalysis());
        analysisContainer.AddPacketAnalysis(AnalysisFixtureFactory.GetTcpPercentageOfDataControlAnalysis());

        analysisContainer.AddTransportLayerConnectionAnalysis(AnalysisFixtureFactory.GetTcpConnectionCounterAnalysis());
        analysisContainer.AddTransportLayerConnectionAnalysis(AnalysisFixtureFactory.GetTcpConnectionRetransmissionAnalysis());
        analysisContainer.AddTransportLayerConnectionAnalysis(AnalysisFixtureFactory.GetTcpConnectionTimingsAnalysis());

        analysisContainer.AddApplicationLayerConnectionAnalysis(tdsConnectionLatencyAnalysis);
        analysisContainer.AddApplicationLayerConnectionAnalysis(tdsLoginConnectionAnalysis);

        _sut = new TdsAnalysisCompositeSection(analysisContainer);
    }

    [Fact]
    public void Render_TextRenderer_RendersTcpRetransmitsGraph()
    {
        // Arrange
        var timestamp = DateTime.Today;

        var timestamp1 = timestamp;
        var timestamp2 = timestamp.AddMinutes(5);
        var timestamp3 = timestamp.AddMinutes(10);
        var timestamp4 = timestamp.AddMinutes(15);
        var timestamp5 = timestamp.AddMinutes(20);

        _tdsConnectionLatencyAnalysisMetrics.AddToList(
            _transportLayerConnection1,
            new TdsConnectionLatencyAnalysisMetrics(
                tdsConnectionLatencies: new TdsConnectionLatencies(
                    lastSuccessfulTdsConnectionState: TdsConnectionState.PreLogin,
                    tcpHandshakeToPreLoginLatency: TimeSpan.FromSeconds(1),
                    lastSuccessfulToLastStateLatency: TimeSpan.FromMilliseconds(150),
                    preLoginToLatestStateLatency: TimeSpan.FromMilliseconds(150),
                    lastPacketTimestamp: timestamp2,
                    totalLatency: TimeSpan.FromSeconds(1.15))));

        _tdsConnectionLatencyAnalysisMetrics.AddToList(
            _transportLayerConnection2,
            new TdsConnectionLatencyAnalysisMetrics(
                tdsConnectionLatencies: new TdsConnectionLatencies(
                    lastSuccessfulTdsConnectionState: TdsConnectionState.PreLoginResponse,
                    tcpHandshakeToPreLoginLatency: TimeSpan.FromSeconds(1),
                    preLoginToPreLoginResponseLatency: TimeSpan.FromMilliseconds(175),
                    lastSuccessfulToLastStateLatency: TimeSpan.FromMilliseconds(100),
                    preLoginToLatestStateLatency: TimeSpan.FromMilliseconds(275),
                    lastPacketTimestamp: timestamp4,
                    totalLatency: TimeSpan.FromSeconds(1.27))));

        AddTdsConnectionMetric(timestamp1, TimeSpan.FromMilliseconds(100));
        AddTdsConnectionMetric(timestamp2, TimeSpan.FromMilliseconds(300));
        AddTdsConnectionMetric(timestamp3, TimeSpan.FromMilliseconds(200));
        AddTdsConnectionMetric(timestamp4, TimeSpan.FromMilliseconds(750));
        AddTdsConnectionMetric(timestamp5, TimeSpan.FromMilliseconds(500));

        var tdsLoginConnectionAnalysisFixture = new TdsLoginConnectionAnalysisFixture(_transportLayerConnection1);

        var tdsLoginConnectionMetrics = new List<TdsLoginConnectionMetrics>
        {
            tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.TcpHandshake, firstCapturedTime: timestamp, duration: TimeSpan.Zero),
            tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.PreLogin, firstCapturedTime: timestamp.AddSeconds(1), duration: TimeSpan.FromSeconds(1)),
            tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.PreLoginResponse, firstCapturedTime: timestamp.AddSeconds(2), duration: TimeSpan.FromSeconds(2)),
            tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.ClientHello, firstCapturedTime: timestamp.AddSeconds(3), duration: TimeSpan.FromSeconds(3)),
            tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.ServerHello, firstCapturedTime: timestamp.AddSeconds(4), duration: TimeSpan.FromSeconds(4)),
            tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.KeyExchange, firstCapturedTime: timestamp.AddSeconds(5), duration: TimeSpan.FromSeconds(5)),
            tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.CipherChange, firstCapturedTime: timestamp.AddSeconds(6), duration: TimeSpan.FromSeconds(6)),
            tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(TdsConnectionState.LoginMessage, firstCapturedTime: timestamp.AddSeconds(7), duration: TimeSpan.FromSeconds(7)),
        };

        _tdsLoginConnectionMetrics.Add(_transportLayerConnection1, tdsLoginConnectionMetrics);

        var expectedResult =
            @"TDS Analysis Report
-------------------

[TDS Failed Login Connections]
A table showing the total failed TDS connections, and how many steps in the login process were captured.

    TH=TcpHandshake, PL=PreLogin, PR=PreLoginResponse, CH=ClientHello, SH=ServerHello,
    KE=KeyExchange, CE=CipherChange, LM=LoginSent, LR=LoginResponse

+-----------+--------------------------------------+----------------------------------------------+---------------------+----------------+
| Frame No. | Failed Connection                    | Login steps                                  | Connection duration | No. of Packets |
+-----------+--------------------------------------+----------------------------------------------+---------------------+----------------+
| 1 -> 16   | 192.168.1.1:1234 -> 192.168.0.1:1433 | TH                                           | 0 ms                | 16             |
| 1 -> 16   | 192.168.1.1:1234 -> 192.168.0.1:1433 | TH -> PL                                     | 1 s                 | 16             |
| 1 -> 16   | 192.168.1.1:1234 -> 192.168.0.1:1433 | TH -> PL -> PR                               | 2 s                 | 16             |
| 1 -> 16   | 192.168.1.1:1234 -> 192.168.0.1:1433 | TH -> PL -> PR -> CH                         | 3 s                 | 16             |
| 1 -> 16   | 192.168.1.1:1234 -> 192.168.0.1:1433 | TH -> PL -> PR -> CH -> SH                   | 4 s                 | 16             |
| 1 -> 16   | 192.168.1.1:1234 -> 192.168.0.1:1433 | TH -> PL -> PR -> CH -> SH -> KE             | 5 s                 | 16             |
| 1 -> 16   | 192.168.1.1:1234 -> 192.168.0.1:1433 | TH -> PL -> PR -> CH -> SH -> KE -> CE       | 6 s                 | 16             |
| 1 -> 16   | 192.168.1.1:1234 -> 192.168.0.1:1433 | TH -> PL -> PR -> CH -> SH -> KE -> CE -> LM | 7 s                 | 16             |
+-----------+--------------------------------------+----------------------------------------------+---------------------+----------------+

[TDS Login Connection Analyses]
A table showing the total successful TDS connections, and how many failures occurred at each step in the login process for each connection.

+----------------------------+---------------------+----+----+----+----+----+----+----+----+
| Connection                 | % Successful Logins | TH | PL | PR | CH | SH | KE | CE | LM |
+----------------------------+---------------------+----+----+----+----+----+----+----+----+
| 192.168.1.1 -> 192.168.0.1 | 0% (0/8)            | 1  | 1  | 1  | 1  | 1  | 1  | 1  | 1  |
+----------------------------+---------------------+----+----+----+----+----+----+----+----+

[TDS Failed Connection Latency]
TDS State Legend:
    TS=TcpSynSent, TH=TcpHandshake, PL=PreLogin, PR=PreLoginResponse, CH=ClientHello, SH=ServerHello, 
    KE=KeyExchange, CE=CipherChange, LM=LoginMessage, LA=LoginAck, LS=LastSuccessful, FA=Failure

+------------------+------------------+-----------------+-------+--------+-------+-------+-------+-------+-------+--------+--------+--------+
| Source           | Destination      | Last successful | TH-PL | PL-PR  | PR-CH | CH-SH | SH-KE | KE-CE | CE-LM | LS-FA  | PL-FA  | TS-FA  |
+------------------+------------------+-----------------+-------+--------+-------+-------+-------+-------+-------+--------+--------+--------+
| 192.168.1.1:1234 | 192.168.0.1:1433 | PL              | 1 s   | _      | _     | _     | _     | _     | _     | 150 ms | 150 ms | 1.15 s |
| 192.168.1.1:1234 | 192.168.0.2:1433 | PR              | 1 s   | 175 ms | _     | _     | _     | _     | _     | 100 ms | 275 ms | 1.27 s |
+------------------+------------------+-----------------+-------+--------+-------+-------+-------+-------+-------+--------+--------+--------+

[TDS Average Connection Latency]
Graph showing TDS average connection latency in milliseconds over the period of the packet capture operation.

   969┤                                                           ╭╮                         
   918┤                                                           ││                         
   867┤                                                           ││                         
   816┤                                                           ││                         
   765┤                                                           ││                         
L  714┤                   ╭╮                                      ││                         
A  663┤                   ││                                      ││                         
T  612┤                   ││                                      ││                         
E  561┤                   ││                                      ││                         
N  510┤                   ││                                      ││                         
C  459┤                   ││                                      ││                  ╭╮     
Y  408┤                   ││                                      ││                  ││     
   357┤                   ││                                      ││                  ││     
m  306┤                   ││                                      ││                  ││     
s  255┤                   ││                                      ││                  ││     
   204┤                   ││                                      ││                  ││     
   153┤                   ││                  ╭╮                  ││                  ││     
   102┤                   ││                  ││                  ││                  ││     
    51┤╮                  ││                  ││                  ││                  ││     
     0┤╰                  ╯╰                  ╯╰                  ╯╰                  ╯╰     
       ----------------|---------------|---------------|---------------|---------------|-----
   00:00:00        00:04:00        00:08:00        00:12:00        00:16:00        00:20:00  
                                TIME PERIOD OF DAY (HH:MM:SS)                                

[TDS Login Failures]
Graph with TDS connection failures over the period of the packet capture operation.

   10┤                                                                                      
T   9┤                                                                                      
D   8┤                                                                                      
S   7┤                                                                                      
    6┤                                                                                      
F   5┤                                                                                      
A   4┤                                                                                      
I   3┤                                                                                      
L   2┤                                                                                      
S   1┤╮         ╭╮         ╭╮          ╭╮         ╭╮          ╭╮         ╭╮          ╭╮     
    0┤╰         ╯╰         ╯╰          ╯╰         ╯╰          ╯╰         ╯╰          ╯╰     
      ----------------|---------------|---------------|---------------|---------------|-----
  00:00:00        00:00:02        00:00:05        00:00:08        00:00:11        00:00:14  
                                TIME PERIOD OF DAY (HH:MM:SS)                               

";

        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }

    private void AddTdsConnectionMetric(DateTime timestamp, TimeSpan latency)
    {
        _tdsConnectionLatencyAnalysisMetrics.AddToList(
            key: _transportLayerConnection1,
            value: new TdsConnectionLatencyAnalysisMetrics(
                new TdsConnectionLatencies
                {
                    LastPacketTimestamp = timestamp,
                    TotalLatency = latency,
                    TdsConnectionState = TdsConnectionState.ConnectionClosedAfterLoginAckTdsState,
                }));
    }
}