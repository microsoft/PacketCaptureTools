// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Timings;
using Microsoft.PacketCapture.Analyzer.Analysis.Metrics;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tcp;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tcp;

public class TcpTrafficTimingsTableSectionTests
{
    private const string HeaderTitle = "TCP Traffic Timings";
    private const string HeaderDescription = "The percentiles of time for connection operations.";
    private const string NoDataMessage = "TCP Traffic Timings table cannot be created - not enough packets to calculate traffic timings were captured.";
    private readonly TcpTrafficTimingsTableSection _sut;

    private readonly TextRenderer _textRenderer;

    private readonly TimestampMetrics _connectionDurations;
    private readonly TimestampMetrics _handshakeDurations;
    private readonly TimestampMetrics _resetAndNextSynDurations;


    public TcpTrafficTimingsTableSectionTests()
    {
        _textRenderer = new TextRenderer();

        _connectionDurations = new TimestampMetrics();
        _handshakeDurations = new TimestampMetrics();
        _resetAndNextSynDurations = new TimestampMetrics();

        var tcpConnectionTimingsAnalysis = new TcpConnectionTimingsAnalysis(
            connectionDurations: _connectionDurations,
            handshakeDurations: _handshakeDurations,
            resetAndNextSynDurations: _resetAndNextSynDurations);

        _sut = new TcpTrafficTimingsTableSection(tcpConnectionTimingsAnalysis);
    }

    [Fact]
    public void Constructor_TcpConnectionTimingsAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "tcpConnectionTimingsAnalysis";

        // Act
        Func<NetworkLayerPacketCountersPerProtocolTableSection> function =
            () => new NetworkLayerPacketCountersPerProtocolTableSection((PacketCounterAnalysis)null!);

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
    public void Render_TextRenderer_RendersPerIpPacketCountersTableSection()
    {
        // Arrange
        _connectionDurations.Insert(TimeSpan.FromMilliseconds(1234));
        _connectionDurations.Insert(TimeSpan.FromMilliseconds(2345));
        _connectionDurations.Insert(TimeSpan.FromMilliseconds(3456));

        _handshakeDurations.Insert(TimeSpan.FromMilliseconds(2345));
        _handshakeDurations.Insert(TimeSpan.FromMilliseconds(3456));
        _handshakeDurations.Insert(TimeSpan.FromMilliseconds(4567));

        _resetAndNextSynDurations.Insert(TimeSpan.FromMilliseconds(3456));
        _resetAndNextSynDurations.Insert(TimeSpan.FromMilliseconds(4567));
        _resetAndNextSynDurations.Insert(TimeSpan.FromMilliseconds(5678));

        var expectedResult =
            $@"[{HeaderTitle}]
{HeaderDescription}

+---------------------+--------+--------+--------+--------+
| Timing              | 50th % | 90th % | 95th % | 99th % |
+---------------------+--------+--------+--------+--------+
| Connection Duration | 2.34 s | 3.45 s | 3.45 s | 3.45 s |
| Handshake Duration  | 3.45 s | 4.56 s | 4.56 s | 4.56 s |
| Between RST and SYN | 4.56 s | 5.67 s | 5.67 s | 5.67 s |
+---------------------+--------+--------+--------+--------+

";

        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }
}