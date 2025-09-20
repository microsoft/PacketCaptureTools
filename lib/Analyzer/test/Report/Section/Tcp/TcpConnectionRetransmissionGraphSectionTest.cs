// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tcp;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tcp;

public class TcpConnectionRetransmissionGraphSectionTest
{
    private const string SectionTitle = "TCP Retransmits";

    private const string HeaderTitle = "TCP Total Outgoing Retransmits Analysis";
    private const string HeaderDescription = "Graph showing TCP retransmits, originating from the capture host, over the period of the packet capture operation.";

    private const string GraphXAxisLabel = "TIME PERIOD OF DAY (HH:MM:SS)";

    private const string NoDataMessage = "TCP retransmission analysis graph cannot be created - captured packets didn't contain any outgoing TCP retransmits.";
    private readonly TcpConnectionRetransmissionGraphSection _sut;

    private readonly TextRenderer _textRenderer;
    private readonly Dictionary<IPAddress, int> _retransmissionsByIpAddress;
    private readonly Dictionary<DateTime, int> _retransmissionsByTime;

    public TcpConnectionRetransmissionGraphSectionTest()
    {
        _textRenderer = new TextRenderer();

        _retransmissionsByIpAddress = [];
        _retransmissionsByTime = [];

        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis(retransmissionsByIpAddress: _retransmissionsByIpAddress, _retransmissionsByTime);

        _sut = new TcpConnectionRetransmissionGraphSection(tcpConnectionRetransmissionAnalysis);
    }

    [Fact]
    public void Constructor_InvalidParameters_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "tcpConnectionRetransmissionAnalysis";

        // Act
        Func<TcpConnectionRetransmissionGraphSection> function = () => new TcpConnectionRetransmissionGraphSection((TcpConnectionRetransmissionAnalysis)null!);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }

    [Fact]
    public void Render_TextRendererNoData_RendersNoDataMessage()
    {
        // Arrange
        var expectedResult =
            $@"{SectionTitle}
---------------

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
        var timestamp = new DateTime(2022, 01, 01, 8, 30, 20);

        _retransmissionsByTime.Add(timestamp.AddSeconds(001), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(002), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(003), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(004), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(005), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(006), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(007), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(008), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(009), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(010), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(011), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(012), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(013), 1);
        _retransmissionsByTime.Add(timestamp.AddSeconds(014), 1);
        _retransmissionsByTime.Add(timestamp.AddSeconds(015), 2);
        _retransmissionsByTime.Add(timestamp.AddSeconds(016), 2);
        _retransmissionsByTime.Add(timestamp.AddSeconds(017), 3);
        _retransmissionsByTime.Add(timestamp.AddSeconds(018), 3);
        _retransmissionsByTime.Add(timestamp.AddSeconds(019), 5);
        _retransmissionsByTime.Add(timestamp.AddSeconds(020), 6);
        _retransmissionsByTime.Add(timestamp.AddSeconds(021), 7);
        _retransmissionsByTime.Add(timestamp.AddSeconds(022), 5);
        _retransmissionsByTime.Add(timestamp.AddSeconds(023), 4);
        _retransmissionsByTime.Add(timestamp.AddSeconds(024), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(025), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(026), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(027), 2);
        _retransmissionsByTime.Add(timestamp.AddSeconds(028), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(029), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(030), 4);
        _retransmissionsByTime.Add(timestamp.AddSeconds(031), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(032), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(033), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(034), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(035), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(036), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(037), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(038), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(039), 0);
        _retransmissionsByTime.Add(timestamp.AddSeconds(040), 2);

        var expectedResult =
            $@"{SectionTitle}
---------------

[{HeaderTitle}]
{HeaderDescription}

   10┤                                                                                      
    9┤                                                                                      
    8┤                                                                                      
    7┤                                        ╭╮                                            
    6┤                                     ╭╮ ││                                            
    5┤                                   ╭╮││ ││╭╮                                          
    4┤                                   ││││ ││││╭╮            ╭╮                          
    3┤                               ╭╮╭╮││││ ││││││            ││                          
    2┤                           ╭╮╭╮││││││││ ││││││      ╭╮    ││                   ╭╮     
    1┤                       ╭╮╭╮││││││││││││ ││││││      ││    ││                   ││     
    0┤─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─╯╰╯╰╯╰╯╰╯╰╯╰╯╰╯╰ ╯╰╯╰╯╰ ─ ─ ─╯╰ ─ ─╯╰ ─ ─ ─ ─ ─ ─ ─ ─ ─ ╯╰     
      ----------------|---------------|---------------|---------------|---------------|-----
  08:30:21        08:30:28        08:30:36        08:30:44        08:30:52        08:31:00  
                                {GraphXAxisLabel}                               

";

        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }
}