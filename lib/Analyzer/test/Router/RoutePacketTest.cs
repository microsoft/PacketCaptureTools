// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Report;
using Microsoft.PacketCapture.Analyzer.Router;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Router;

public class RoutePacketTest
{
    private const string HelpText = "Visit this link for more information or to report issues and submit feedback.";

    private static readonly IAnalysisConfiguration Configuration = new DefaultTrafficAnalysisConfiguration(new SessionMetadata());
    private static readonly PacketContentReader PacketContentReader = new(Configuration);

    [Fact]
    public void Test_RoutePacket_To_See_If_Routing_Correctly_To_Analysis()
    {
        // Arrange
        byte[] bytes = [0, 12, 41, 240, 15, 112, 0, 12, 41, 188, 231, 25, 8, 0, 69, 0, 0, 40, 117, 154, 64, 0, 128, 6, 37, 27, 192, 168, 111, 100, 192, 168, 111, 101, 1, 133, 202, 169, 53, 209, 180, 212, 238, 48, 190, 148, 80, 20, 0, 0, 236, 27, 0, 0, 0, 0, 0, 0, 0, 0];
        
        PacketContentReader.TryGetPhysicalFrame(bytes, bytes.Length, out var physicalFrame);
        var packet = new CapturedPacket(bytes, bytes.Length, DateTime.Now, 1, physicalFrame);
        var referenceIpAddress = new IPAddress([192, 168, 111, 100]);
        IEnumerable<IPAddress> referenceIpAddresses = new HashSet<IPAddress> { referenceIpAddress };
        IPacketFlowDetector packetFlowDetector = new ReferenceIpPacketFlowDetector(referenceIpAddresses);
        var analysis = new TcpPacketResetAnalysis(packetFlowDetector);
        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText) { PacketAnalyses = [analysis] };
        var router = new PacketRouter(config);

        // Act
        router.RoutePacket(packet);
        router.RoutePacket(packet);
        router.RoutePacket(packet);

        // Assert
        analysis.GlobalCount.Should().Be(3);
    }

    [Fact]
    public void Test_RoutePacket_Null_Parameters_Should_Not_Be_Valid()
    {
        // Act
        Action check = () =>
        {
            var router = new PacketRouter(null!);
        };

        // Assert
        check.Should().Throw<ArgumentNullException>();
    }
}