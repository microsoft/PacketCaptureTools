// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Packet;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Packet;

public class ThroughputAnalysisTest
{
    private static readonly byte[] PacketBytes = new byte[60];

    [Fact]
    public void Test_ThroughputAnalysis_Zero_Or_One_Packets_Should_Return_All_Zero_For_Averages()
    {
        // Arrange
        var firstPacketTime = DateTime.Parse("1970-01-01 00:01:00");
        var throughputAnalysisZero = new ThroughputAnalysis();
        var throughputAnalysisOne = new ThroughputAnalysis();
        var throughputAnalysisTwo = new ThroughputAnalysis();
        var earlyPacket = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime, 1, null);
        var middlePacket = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(0.1), 1, null);
        var laterPacket = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(0.2), 1, null);

        // Act
        throughputAnalysisOne.Process(earlyPacket);

        // throughputAnalysisTwo is used to test packets under 1 second time interval, 100 ms. 
        throughputAnalysisTwo.Process(earlyPacket);
        throughputAnalysisTwo.Process(middlePacket);
        throughputAnalysisTwo.Process(laterPacket);

        // Assert
        throughputAnalysisZero.AverageNumberOfPackets.Should().Be(0);
        throughputAnalysisZero.MaxNumberOfPackets.Should().Be(0);
        throughputAnalysisZero.MinNumberOfPackets.Should().Be(0);

        throughputAnalysisZero.AverageSpeedOfDataTransfer.Should().Be(0);
        throughputAnalysisZero.MaxSpeedOfDataTransfer.Should().Be(0);
        throughputAnalysisZero.MinSpeedOfDataTransfer.Should().Be(0);

        throughputAnalysisOne.AverageNumberOfPackets.Should().Be(1);
        throughputAnalysisOne.MaxNumberOfPackets.Should().Be(1);
        throughputAnalysisOne.MinNumberOfPackets.Should().Be(1);

        throughputAnalysisOne.AverageSpeedOfDataTransfer.Should().Be(60);
        throughputAnalysisOne.MaxSpeedOfDataTransfer.Should().Be(60);
        throughputAnalysisOne.MinSpeedOfDataTransfer.Should().Be(60);

        throughputAnalysisTwo.AverageNumberOfPackets.Should().BeApproximately(15, 0.001);
        throughputAnalysisTwo.MaxNumberOfPackets.Should().Be(15);
        throughputAnalysisTwo.MinNumberOfPackets.Should().Be(15);

        throughputAnalysisTwo.AverageSpeedOfDataTransfer.Should().BeApproximately(900, 0.001);
        throughputAnalysisTwo.MaxSpeedOfDataTransfer.Should().Be(900);
        throughputAnalysisTwo.MinSpeedOfDataTransfer.Should().Be(900);
    }

    [Fact]
    public void Test_ThroughputAnalysis_Maximum_Minimum_Values_Shoul_Be_Correct()
    {
        // Arrange
        var firstPacketTime = DateTime.Parse("1970-01-01 00:01:00");
        var throughputAnalysis = new ThroughputAnalysis();

        // Create Mock packets so that Minimum Packet Count= 4, Maximum Packet Count = 7
        // Add two packet to first partial second
        var packet_0_0 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(0.3), 1, null);
        var packet_0_1 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(0.7), 1, null);

        // Add four packets to second full second
        var packet_1_0 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(1.0), 1, null);
        var packet_1_1 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(1.1), 1, null);
        var packet_1_2 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(1.2), 1, null);
        var packet_1_3 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(1.3), 1, null);

        // Add seven packets to last partial second
        var packet_2_0 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(2.0), 1, null);
        var packet_2_1 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(2.1), 1, null);
        var packet_2_2 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(2.2), 1, null);
        var packet_2_3 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(2.3), 1, null);
        var packet_2_4 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(2.4), 1, null);
        var packet_2_5 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(2.5), 1, null);
        var packet_2_6 = new CapturedPacket(PacketBytes, PacketBytes.Length, firstPacketTime.AddSeconds(2.9), 1, null);

        // Act
        throughputAnalysis.Process(packet_0_0);
        throughputAnalysis.Process(packet_0_1);
                                   
        throughputAnalysis.Process(packet_1_0);
        throughputAnalysis.Process(packet_1_1);
        throughputAnalysis.Process(packet_1_2);
        throughputAnalysis.Process(packet_1_3);
                                   
        throughputAnalysis.Process(packet_2_0);
        throughputAnalysis.Process(packet_2_1);
        throughputAnalysis.Process(packet_2_2);
        throughputAnalysis.Process(packet_2_3);
        throughputAnalysis.Process(packet_2_4);
        throughputAnalysis.Process(packet_2_5);
        throughputAnalysis.Process(packet_2_6);

        // Assert
        throughputAnalysis.AverageNumberOfPackets.Should().BeApproximately(5, 0.1);
        throughputAnalysis.MaxNumberOfPackets.Should().Be(7);
        throughputAnalysis.MinNumberOfPackets.Should().Be(4);

        throughputAnalysis.AverageSpeedOfDataTransfer.Should().BeApproximately(300, 0.1);
        throughputAnalysis.MaxSpeedOfDataTransfer.Should().Be(420);
        throughputAnalysis.MinSpeedOfDataTransfer.Should().Be(240);
    }

    [Fact]
    public void Test_ThroughputAnalysis_Basic_Parameters_Should_Be_Valid()
    {
        // Arrange
        var throughputAnalysis = new ThroughputAnalysis();
        var earlyPacket = new CapturedPacket(PacketBytes, PacketBytes.Length, DateTime.MinValue, 1, null);
        var laterPacket = new CapturedPacket(PacketBytes, PacketBytes.Length, DateTime.MinValue.AddSeconds(60), 1, null);

        // Act
        throughputAnalysis.Process(earlyPacket);
        throughputAnalysis.Process(laterPacket);

        // Assert
        throughputAnalysis.AverageNumberOfPackets.Should().BeApproximately(0.033, 0.001);
        throughputAnalysis.MaxNumberOfPackets.Should().Be(1);
        throughputAnalysis.MinNumberOfPackets.Should().Be(0);

        throughputAnalysis.AverageSpeedOfDataTransfer.Should().Be((double)(PacketBytes.Length * 2) / 60);
        throughputAnalysis.MaxSpeedOfDataTransfer.Should().Be(PacketBytes.Length);
        throughputAnalysis.MinSpeedOfDataTransfer.Should().Be(0);
    }

    [Fact]
    public void Test_ThroughputAnalysis_Null_Packets_Should_Fast_Return()
    {
        // Arrange
        var throughputAnalysisNullPacket = new ThroughputAnalysis();
        var throughputAnalysisNullPacketTime = new ThroughputAnalysis();
        var nullPacketTime = new CapturedPacket(PacketBytes, PacketBytes.Length, null, 1, null);

        // Act
        throughputAnalysisNullPacket.Process(null!);
        throughputAnalysisNullPacketTime.Process(nullPacketTime);

        // Assert
        throughputAnalysisNullPacket.AverageNumberOfPackets.Should().Be(0);
        throughputAnalysisNullPacket.MaxNumberOfPackets.Should().Be(0);
        throughputAnalysisNullPacket.MinNumberOfPackets.Should().Be(0);

        throughputAnalysisNullPacket.AverageSpeedOfDataTransfer.Should().Be(0);
        throughputAnalysisNullPacket.MaxSpeedOfDataTransfer.Should().Be(0);
        throughputAnalysisNullPacket.MinSpeedOfDataTransfer.Should().Be(0);

        throughputAnalysisNullPacketTime.AverageNumberOfPackets.Should().Be(0);
        throughputAnalysisNullPacketTime.MaxNumberOfPackets.Should().Be(0);
        throughputAnalysisNullPacketTime.MinNumberOfPackets.Should().Be(0);

        throughputAnalysisNullPacketTime.AverageSpeedOfDataTransfer.Should().Be(0);
        throughputAnalysisNullPacketTime.MaxSpeedOfDataTransfer.Should().Be(0);
        throughputAnalysisNullPacketTime.MinSpeedOfDataTransfer.Should().Be(0);
    }
}