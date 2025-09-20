// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tds;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tds;

public class TdsAverageLoginLatencyGraphSectionTests
{
    private const string HeaderTitle = "TDS Average Connection Latency";

    private const string HeaderDescription = "Graph showing TDS average connection latency in milliseconds over the period of the packet capture operation.";

    private const string GraphXAxisLabel = "TIME PERIOD OF DAY (HH:MM:SS)";

    private const string NoDataMessage = "TDS Average Connection Latency graph cannot be created - captured packets didn't contain any TDS latencies.";
    private readonly TdsAverageLoginLatencyGraphSection _sut;

    private readonly TextRenderer _textRenderer;
    private readonly Dictionary<TransportLayerConnection, List<TdsConnectionLatencyAnalysisMetrics>> _tdsConnectionLatencyAnalysisMetrics;
    private readonly TransportLayerConnection _connection;

    public TdsAverageLoginLatencyGraphSectionTests()
    {
        _textRenderer = new TextRenderer();
        _tdsConnectionLatencyAnalysisMetrics = [];
        _connection = new TransportLayerConnection(IPAddress.Any, IPAddress.Any, 1, 1);

        var tdsConnectionLatencyAnalysis = new TdsConnectionLatencyAnalysis(tdsConnectionLatencyAnalysisMetrics: _tdsConnectionLatencyAnalysisMetrics);

        _sut = new TdsAverageLoginLatencyGraphSection(tdsConnectionLatencyAnalysis);
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
    public void Render_TextRenderer_RendersTcpRetransmitsGraph()
    {
        // Arrange
        var timestamp1 = new DateTime(2022, 6, 20, 13, 48, 1);
        var timestamp2 = timestamp1.AddMinutes(10);
        var timestamp3 = timestamp1.AddMinutes(30);
        var timestamp4 = timestamp1.AddMinutes(60);
        var timestamp5 = timestamp1.AddMinutes(120);
        var timestamp6 = timestamp1.AddMinutes(140);
        var timestamp7 = timestamp1.AddMinutes(170);
        var timestamp8 = timestamp1.AddMinutes(180);
        var timestamp9 = timestamp1.AddMinutes(200);

        AddTdsConnectionMetric(timestamp1, TimeSpan.FromMilliseconds(100));
        AddTdsConnectionMetric(timestamp2, TimeSpan.FromMilliseconds(1000));
        AddTdsConnectionMetric(timestamp3, TimeSpan.FromMilliseconds(200));
        AddTdsConnectionMetric(timestamp4, TimeSpan.FromMilliseconds(750));
        AddTdsConnectionMetric(timestamp5, TimeSpan.FromMilliseconds(500));
        AddTdsConnectionMetric(timestamp6, TimeSpan.FromMilliseconds(125));
        AddTdsConnectionMetric(timestamp7, TimeSpan.FromMilliseconds(600));
        AddTdsConnectionMetric(timestamp8, TimeSpan.FromMilliseconds(250));
        AddTdsConnectionMetric(timestamp9, TimeSpan.FromMilliseconds(400));

        var expectedResult =
            $@"[{HeaderTitle}]
{HeaderDescription}

   1000┤   ╭╮                                                                                 
    950┤   ││                                                                                 
    900┤   ││                                                                                 
    850┤   ││                                                                                 
    800┤   ││                                                                                 
L   750┤   ││                  ╭╮                                                             
A   700┤   ││                  ││                                                             
T   650┤   ││                  ││                                                             
E   600┤   ││                  ││                                          ╭╮                 
N   550┤   ││                  ││                                          ││                 
C   500┤   ││                  ││                      ╭╮                  ││                 
Y   450┤   ││                  ││                      ││                  ││                 
    400┤   ││                  ││                      ││                  ││          ╭╮     
m   350┤   ││                  ││                      ││                  ││          ││     
s   300┤   ││                  ││                      ││                  ││          ││     
    250┤   ││                  ││                      ││                  ││  ╭╮      ││     
    200┤   ││      ╭╮          ││                      ││                  ││  ││      ││     
    150┤   ││      ││          ││                      ││                  ││  ││      ││     
    100┤╮  ││      ││          ││                      ││      ╭╮          ││  ││      ││     
     50┤│  ││      ││          ││                      ││      ││          ││  ││      ││     
      0┤╰  ╯╰      ╯╰          ╯╰                      ╯╰      ╯╰          ╯╰  ╯╰      ╯╰     
        ----------------|---------------|---------------|---------------|---------------|-----
    13:48:01        14:28:01        15:08:01        15:48:01        16:28:01        17:08:01  
                                 {GraphXAxisLabel}                                

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
            key: _connection,
            value: new TdsConnectionLatencyAnalysisMetrics(
                new TdsConnectionLatencies
                {
                    LastPacketTimestamp = timestamp,
                    TotalLatency = latency,
                }));
    }
}