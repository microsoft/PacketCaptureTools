// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Packet;

public class TransportLayerPacketCountersPerProtocolTableSectionTests
{
    private const string HeaderTitle = "Transport Layer";
    private const string NoDataMessage = "Transport Layer table cannot be created - no transport layer packets were captured.";
    private readonly TransportLayerPacketCountersPerProtocolTableSection _sut;

    private readonly TextRenderer _textRenderer;

    private static readonly IEnumerable<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> { IPAddress.Parse("192.168.0.1") };

    private readonly IPacketFlowDetector _packetFlowDetector;

    private readonly Dictionary<TransportSegmentProtocol, int> _incomingCountByTransportSegmentProtocol;
    private readonly Dictionary<TransportSegmentProtocol, int> _outgoingCountByTransportSegmentProtocol;

    public TransportLayerPacketCountersPerProtocolTableSectionTests()
    {
        _textRenderer = new TextRenderer();

        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);

        _incomingCountByTransportSegmentProtocol = [];
        _outgoingCountByTransportSegmentProtocol = [];

        var packetCounterAnalysis = new PacketCounterAnalysis(
            packetFlowDetector: _packetFlowDetector,
            tdsPorts: new HashSet<int> { 1 },
            incomingCountByTransportSegmentProtocol: _incomingCountByTransportSegmentProtocol,
            outgoingCountByTransportSegmentProtocol: _outgoingCountByTransportSegmentProtocol);

        _sut = new TransportLayerPacketCountersPerProtocolTableSection(packetCounterAnalysis);

        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
    }

    [Fact]
    public void Constructor_PacketCounterAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "packetCounterAnalysis";

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
        _incomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP] = 1000;
        _outgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP] = 200;
        _incomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP] = 50;
        _outgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP] = 60;

        var expectedResult =
            $@"[{HeaderTitle}]

+----------+-------+------------+----------+------+
| Protocol | Count | Percentage | Received | Sent |
+----------+-------+------------+----------+------+
| TCP      | 1200  | 91.60 %    | 1000     | 200  |
| UDP      | 110   | 8.40 %     | 50       | 60   |
+----------+-------+------------+----------+------+

";

        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }
}