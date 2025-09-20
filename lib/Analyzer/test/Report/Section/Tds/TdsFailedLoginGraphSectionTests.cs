// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tds;
using Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tds.Fixtures;
using System;
using System.Collections.Generic;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tds;

public class TdsFailedLoginGraphSectionTests
{
    private const string GraphHeaderTitle = "TDS Login Failures";

    private const string GraphHeaderDescription = "Graph with TDS connection failures over the period of the packet capture operation.";

    private const string GraphXAxisLabel = "TIME PERIOD OF DAY (HH:MM:SS)";

    private const string NoDataMessage = "TDS Login Failures graph cannot be created - captured packets didn't contain any failed TDS logins.";
    private readonly TdsFailedLoginGraphSection _sut;
    private readonly TextRenderer _textRenderer;
    private readonly TdsLoginConnectionAnalysisFixture _tdsLoginConnectionAnalysisFixture;
    private readonly Dictionary<TransportLayerConnection, List<TdsLoginConnectionMetrics>> _connectionStates;

    public TdsFailedLoginGraphSectionTests()
    {
        _textRenderer = new TextRenderer();
        _connectionStates = [];

        _tdsLoginConnectionAnalysisFixture = new TdsLoginConnectionAnalysisFixture();

        var tdsLoginConnectionAnalyis = new TdsLoginConnectionAnalysis(_connectionStates);
        _sut = new TdsFailedLoginGraphSection(tdsLoginConnectionAnalyis);
    }

    [Fact]
    public void Constructor_InvalidParams_ThrowsException()
    {
        // Arrange
        var argumentName = "tdsConnectionAnalysis";

        // Act
        Func<TdsFailedLoginGraphSection> function = () => new TdsFailedLoginGraphSection((TdsLoginConnectionAnalysis)null!);

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
        var timestamp = DateTime.Today;
        
        for (var i = 0; i < 20; i++)
        {
            _connectionStates.AddToList(_tdsLoginConnectionAnalysisFixture.GetTransportLayerConnection(), _tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(firstCapturedTime: timestamp.AddSeconds(i), tdsConnectionState: TdsConnectionState.ClientHello));
        }

        for (var i = 5; i < 10; i++)
        {
            _connectionStates.AddToList(_tdsLoginConnectionAnalysisFixture.GetTransportLayerConnection(), _tdsLoginConnectionAnalysisFixture.GetTdsLoginConnectionMetrics(firstCapturedTime: timestamp.AddSeconds(i), tdsConnectionState: TdsConnectionState.ClientHello));
        }

        var expectedResult =
            $@"[{GraphHeaderTitle}]
{GraphHeaderDescription}

   10┤                                                                                      
T   9┤                                                                                      
D   8┤                                                                                      
S   7┤                                                                                      
    6┤                                                                                      
F   5┤                                                                                      
A   4┤                                                                                      
I   3┤                                                                                      
L   2┤                    ╭╮  ╭╮  ╭╮  ╭╮  ╭╮                                                
S   1┤╮  ╭╮  ╭╮  ╭╮  ╭╮   ││  ││  ││  ││  ││   ╭╮  ╭╮  ╭╮  ╭╮  ╭╮   ╭╮  ╭╮  ╭╮  ╭╮   ╭╮     
    0┤╰  ╯╰  ╯╰  ╯╰  ╯╰   ╯╰  ╯╰  ╯╰  ╯╰  ╯╰   ╯╰  ╯╰  ╯╰  ╯╰  ╯╰   ╯╰  ╯╰  ╯╰  ╯╰   ╯╰     
      ----------------|---------------|---------------|---------------|---------------|-----
  00:00:00        00:00:03        00:00:07        00:00:11        00:00:15        00:00:19  
                                {GraphXAxisLabel}                               

";
        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }
}