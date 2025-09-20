// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Packet;

public class NetworkLayerPacketCountersPerProtocolTableSectionTests
{
    private const string HeaderTitle = "Network Layer";
    private const string NoDataMessage = "Network Layer table cannot be created - no network layer packets were captured.";
    private readonly NetworkLayerPacketCountersPerProtocolTableSection _sut;

    private readonly TextRenderer _textRenderer;

    private static readonly IEnumerable<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> { IPAddress.Parse("192.168.0.1") };

    private readonly IPacketFlowDetector _packetFlowDetector;

    private readonly Dictionary<NetworkPacketProtocol, int> _incomingCountByNetworkPacketProtocol;
    private readonly Dictionary<NetworkPacketProtocol, int> _outgoingCountByNetworkPacketProtocol;

    public NetworkLayerPacketCountersPerProtocolTableSectionTests()
    {
        _textRenderer = new TextRenderer();

        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);

        _incomingCountByNetworkPacketProtocol = [];
        _outgoingCountByNetworkPacketProtocol = [];

        var packetCounterAnalysis = new PacketCounterAnalysis(
            packetFlowDetector: _packetFlowDetector,
            tdsPorts: new HashSet<int> { 1 },
            incomingCountByNetworkPacketProtocol: _incomingCountByNetworkPacketProtocol,
            outgoingCountByNetworkPacketProtocol: _outgoingCountByNetworkPacketProtocol);

        _sut = new NetworkLayerPacketCountersPerProtocolTableSection(packetCounterAnalysis);
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
        _incomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4] = 10;
        _outgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4] = 20;
        _incomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6] = 50;
        _outgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6] = 80;

        var expectedResult =
            $@"[{HeaderTitle}]

+----------+-------+------------+----------+------+
| Protocol | Count | Percentage | Received | Sent |
+----------+-------+------------+----------+------+
| IPv4     | 30    | 18.75 %    | 10       | 20   |
| IPv6     | 130   | 81.25 %    | 50       | 80   |
+----------+-------+------------+----------+------+

";

        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }
}