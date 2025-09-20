// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Packet;

public class PacketCountersPerProtocolCompositeSectionFunctionalTests
{
    private const string CompositeHeaderTitle = "Packet Counters per protocol";
    private const string CompositeHeaderDescription = "The percent and count of packets received / sent for each protocol.";

    private const string NetworkLayerHeaderTitle = "Network Layer";
    private const string TransportLayerHeaderTitle = "Transport Layer";

    private const string NetworkLayerNoDataMessage = "Network Layer table cannot be created - no network layer packets were captured.";
    private const string TransportLayerNoDataMessage = "Transport Layer table cannot be created - no transport layer packets were captured.";
    private readonly PacketCountersPerProtocolCompositeSection _sut;

    private readonly TextRenderer _textRenderer;

    private readonly IEnumerable<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> { IPAddress.Parse("192.168.0.1") };

    private readonly IPacketFlowDetector _packetFlowDetector;

    private readonly Dictionary<NetworkPacketProtocol, int> _incomingCountByNetworkPacketProtocol;
    private readonly Dictionary<NetworkPacketProtocol, int> _outgoingCountByNetworkPacketProtocol;
    private readonly Dictionary<TransportSegmentProtocol, int> _incomingCountByTransportSegmentProtocol;
    private readonly Dictionary<TransportSegmentProtocol, int> _outgoingCountByTransportSegmentProtocol;

    public PacketCountersPerProtocolCompositeSectionFunctionalTests()
    {
        _textRenderer = new TextRenderer();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _incomingCountByNetworkPacketProtocol = [];
        _outgoingCountByNetworkPacketProtocol = [];
        _incomingCountByTransportSegmentProtocol = [];
        _outgoingCountByTransportSegmentProtocol = [];

        var analysisContainer = new AnalysisContainer();

        analysisContainer.AddPacketAnalysis(AnalysisFixtureFactory.GetPacketCounterAnalysis(
            packetFlowDetector: _packetFlowDetector,
            incomingCountByNetworkPacketProtocol: _incomingCountByNetworkPacketProtocol,
            outgoingCountByNetworkPacketProtocol: _outgoingCountByNetworkPacketProtocol,
            incomingCountByTransportSegmentProtocol: _incomingCountByTransportSegmentProtocol,
            outgoingCountByTransportSegmentProtocol: _outgoingCountByTransportSegmentProtocol));
        analysisContainer.AddPacketAnalysis(AnalysisFixtureFactory.GetThroughputAnalysis());
        analysisContainer.AddPacketAnalysis(AnalysisFixtureFactory.GetTcpPacketResetAnalysis());
        analysisContainer.AddPacketAnalysis(AnalysisFixtureFactory.GetTcpPercentageOfDataControlAnalysis());

        _sut = new PacketCountersPerProtocolCompositeSection(analysisContainer);
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
            $@"[{CompositeHeaderTitle}]
{CompositeHeaderDescription}

{NetworkLayerNoDataMessage}

{TransportLayerNoDataMessage}

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
        _incomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4] = 10;
        _outgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4] = 20;
        _incomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6] = 50;
        _outgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6] = 80;

        _incomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP] = 1000;
        _outgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP] = 200;
        _incomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP] = 50;
        _outgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP] = 60;

        var expectedResult =
            $@"[{CompositeHeaderTitle}]
{CompositeHeaderDescription}

[{NetworkLayerHeaderTitle}]

+----------+-------+------------+----------+------+
| Protocol | Count | Percentage | Received | Sent |
+----------+-------+------------+----------+------+
| IPv4     | 30    | 18.75 %    | 10       | 20   |
| IPv6     | 130   | 81.25 %    | 50       | 80   |
+----------+-------+------------+----------+------+

[{TransportLayerHeaderTitle}]

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