// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tcp;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tcp;

public class TcpPacketResetGraphSectionTest
{
    private const string SectionTitle = "TCP Resets";

    private const string HeaderTitle = "TCP Total Reset Analysis";
    private const string HeaderDescription = "Graph showing TCP connection resets over the period of the packet capture operation.";

    private const string GraphXAxisLabel = "TIME PERIOD OF DAY (HH:MM:SS)";

    private const string NoDataMessage = "TCP reset analysis analysis graph cannot be created - captured packets didn't contain any TCP resets.";
    private readonly TcpPacketResetGraphSection _sut;

    private readonly TextRenderer _textRenderer;
    private readonly Dictionary<(IPAddress sourceAddress, IPAddress destinationAddress, int sourcePort, int destinationPort), int> _countByConnection;
    private readonly Dictionary<DateTime, int> _countBySecond;
    private readonly Dictionary<IPAddress, (int asSource, int asDestination)> _perIpResetCount;

    private static readonly IPAddress _referenceIpAddress = new([192, 168, 111, 100]);
    private static readonly IEnumerable<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> { _referenceIpAddress };
    private readonly IPacketFlowDetector _packetFlowDetector;

    public TcpPacketResetGraphSectionTest()
    {
        _textRenderer = new TextRenderer();

        _countByConnection = [];
        _countBySecond = [];
        _perIpResetCount = [];
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);

        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(
            packetFlowDetector: _packetFlowDetector,
            countByConnection: _countByConnection,
            countBySecond: _countBySecond,
            perIpResetCount: _perIpResetCount);

        _sut = new TcpPacketResetGraphSection(tcpPacketResetAnalysis);
    }

    [Fact]
    public void Constructor_InvalidParameters_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "tcpPacketResetAnalysis";

        // Act
        Func<TcpPacketResetGraphSection> function = () => new TcpPacketResetGraphSection((TcpPacketResetAnalysis)null!);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }

    [Fact]
    public void Render_TextRendererNoData_RendersNoDataMessage()
    {
        // Arrange
        var expectedResult =
            $@"{SectionTitle}
----------

{NoDataMessage}

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
        var timestamp = new DateTime(2022, 6, 20, 13, 48, 1);

        _countBySecond.Add(timestamp, 1);
        _countBySecond.Add(timestamp.AddSeconds(200), 1);
        _countBySecond.Add(timestamp.AddMinutes(120), 2);

        var expectedResult =
            $@"{SectionTitle}
----------

[{HeaderTitle}]
{HeaderDescription}

T  10┤                                                                                      
C   9┤                                                                                      
P   8┤                                                                                      
    7┤                                                                                      
R   6┤                                                                                      
E   5┤                                                                                      
S   4┤                                                                                      
E   3┤                                                                                      
T   2┤                                                                               ╭╮     
S   1┤╮╭╮                                                                            ││     
    0┤╰╯╰                                                                            ╯╰     
      ----------------|---------------|---------------|---------------|---------------|-----
  13:48:01        14:12:01        14:36:01        15:00:01        15:24:01        15:48:01  
                                {GraphXAxisLabel}                               

";

        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }
}