// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Report;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Router;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Controller.Configuration.Tds;

public class TdsTrafficAnalysisConfigurationTest
{
    private const string HelpText = "Visit this link for more information or to report issues and submit feedback.";
    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly TextRenderer _textRenderer;

    private readonly ISet<IPAddress> _captureIpAddresses = new HashSet<IPAddress>
    {
        IPAddress.Parse("192.168.0.1"),
    };
    private readonly IPAddress _remoteIpAddress = IPAddress.Parse("192.168.1.1");

    public TdsTrafficAnalysisConfigurationTest()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _textRenderer = new TextRenderer();
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
    }

    [Fact]
    public void ReportRender_PacketsHaveResetsHaveRetransmits_RenderReportWithResetsAndRetransmits()
    {
        // Arrange
        var sessionMetadata = new SessionMetadata(captureAddresses: _captureIpAddresses);
        var tdsTrafficAnalysisConfiguration = new TdsTrafficAnalysisConfiguration(sessionMetadata, HelpText);
        var packetRouter = new PacketRouter(tdsTrafficAnalysisConfiguration);

        var capturedDateTime = new DateTime(2022, 01, 01, 08, 30, 20);

        var packets = new[]
        {
            GetCapturedPacketFixture(
                capturedDateTime: capturedDateTime),

            GetCapturedPacketFixture(
                capturedDateTime: capturedDateTime.AddMinutes(1),
                hasPayload: true),

            GetCapturedPacketFixture(
                capturedDateTime: capturedDateTime.AddMinutes(2),
                hasPayload: true),

            GetCapturedPacketFixture(
                capturedDateTime: capturedDateTime.AddMinutes(3),
                hasPayload: true),

            GetCapturedPacketFixture(
                capturedDateTime: capturedDateTime.AddMinutes(4),
                tcpFlags: new TcpFlags(rst: true)),

            GetCapturedPacketFixture(
                capturedDateTime: capturedDateTime.AddMinutes(5),
                hasPayload: true),

            GetCapturedPacketFixture(
                capturedDateTime: capturedDateTime.AddMinutes(6),
                tcpFlags: new TcpFlags(rst: true)),

            GetCapturedPacketFixture(
                capturedDateTime: capturedDateTime.AddMinutes(7)),
        };

        var expectedResult =
            @"Metadata
--------

Metadata on the packet capture, packet analysis and report generation process.

+--------------------+-------+
| Name               | Value |
+--------------------+-------+
| Capture start time | N/A   |
| Capture end time   | N/A   |
| Capture duration   | N/A   |
| Report version     | v1.0  |
+--------------------+-------+

Packet Counters
---------------

[Global Packet Counters]
A Total breakdown of all captured packets metrics.

+---------------+-------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+
| Total Packets | TCP Packets | TDS Packets | Resets | Retransmits | TCP Connections | TCP Sent | TCP Received | TCP Control % | TCP Data % |
+---------------+-------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+
| 8             | 8           | 0           | 2      | 3           | 1               | 4 B      | 0 B          | 0.00 %        | 100.00 %   |
+---------------+-------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+

[Packet Counters per protocol]
The percent and count of packets received / sent for each protocol.

[Network Layer]

+----------+-------+------------+----------+------+
| Protocol | Count | Percentage | Received | Sent |
+----------+-------+------------+----------+------+
| IPv4     | 8     | 100.00 %   | 0        | 8    |
| IPv6     | 0     | 0.00 %     | 0        | 0    |
| ARP      | 0     | 0.00 %     | 0        | 0    |
+----------+-------+------------+----------+------+

[Transport Layer]

+----------+-------+------------+----------+------+
| Protocol | Count | Percentage | Received | Sent |
+----------+-------+------------+----------+------+
| TCP      | 8     | 100.00 %   | 0        | 8    |
| UDP      | 0     | 0.00 %     | 0        | 0    |
+----------+-------+------------+----------+------+

[Throughput]
The average, minimum and maximum number of packets and data transferred per second.

+-------------------+----------+-------+-------+
| Value             | Average  | Min   | Max   |
+-------------------+----------+-------+-------+
| Number of Packets | 0.019 /s | 0 /s  | 1 /s  |
| Speed             | 0 B/s    | 0 B/s | 0 B/s |
+-------------------+----------+-------+-------+

[Per IP Packet Counters]
A Total breakdown of all captured packets metrics by IP address.

+-------------+---------------+-------------+-------------+-------------------+-------------+-----------------------------------------+----------------+
| Dst IP      | Total Packets | TCP Packets | TDS Packets | Resets (src, dst) | Retransmits | TCP Connections (New, Existing, Closed) | Average RTT(s) |
+-------------+---------------+-------------+-------------+-------------------+-------------+-----------------------------------------+----------------+
| 192.168.1.1 | 8             | 8           | 0           | (0, 2)            | 3           | (1, 0, 1)                               | 0.000          |
+-------------+---------------+-------------+-------------+-------------------+-------------+-----------------------------------------+----------------+

TCP Traffic Timings table cannot be created - not enough packets to calculate traffic timings were captured.

TCP Resets
----------

[TCP Total Reset Analysis]
Graph showing TCP connection resets over the period of the packet capture operation.

T  10┤                                                                                      
C   9┤                                                                                      
P   8┤                                                                                      
    7┤                                                                                      
R   6┤                                                                                      
E   5┤                                                                                      
S   4┤                                                                                      
E   3┤                                                                                      
T   2┤                                                                                      
S   1┤                                            ╭╮                     ╭╮                 
    0┤─          ─          ─           ─         ╯╰           ─         ╯╰           ─     
      ----------------|---------------|---------------|---------------|---------------|-----
  08:30:20        08:31:44        08:33:08        08:34:32        08:35:56        08:37:20  
                                TIME PERIOD OF DAY (HH:MM:SS)                               

TCP Retransmits
---------------

[TCP Total Outgoing Retransmits Analysis]
Graph showing TCP retransmits, originating from the capture host, over the period of the packet capture operation.

   10┤                                                                                      
    9┤                                                                                      
    8┤                                                                                      
    7┤                                                                                      
    6┤                                                                                      
    5┤                                                                                      
    4┤                                                                                      
    3┤                                                                                      
    2┤                                                                                      
    1┤╮                        ╭╮                                                    ╭╮     
    0┤╰                        ╯╰                                                    ╯╰     
      ----------------|---------------|---------------|---------------|---------------|-----
  08:32:20        08:32:56        08:33:32        08:34:08        08:34:44        08:35:20  
                                TIME PERIOD OF DAY (HH:MM:SS)                               

TDS Analysis Report
-------------------

TDS Failed Login Connections table cannot be created - captured packets didn't contain any TDS failed login connections.

TDS Login Connection Analyses table cannot be created - captured packets didn't contain any TDS login connections.

TDS Failed Connection Latency table cannot be created - captured packets didn't contain any failed TDS connections.

TDS Average Connection Latency graph cannot be created - captured packets didn't contain any TDS latencies.

TDS Login Failures graph cannot be created - captured packets didn't contain any failed TDS logins.

Help
----

Visit this link for more information or to report issues and submit feedback.

";

        // Act
        foreach (var capturedPacket in packets)
        {
            packetRouter.RoutePacket(capturedPacket);
        }

        tdsTrafficAnalysisConfiguration.Report.Render(_textRenderer);

        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }

    private CapturedPacket GetCapturedPacketFixture(
        DateTime capturedDateTime,
        IPAddress? captureIpAddress = null,
        IPAddress? remoteIpAddress = null,
        TcpFlags? tcpFlags = null,
        bool hasPayload = false)
    {
        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            tcpFlags: tcpFlags,
            payloadSize: (uint)(hasPayload ? 1 : 0));

        var iPv4Packet = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: captureIpAddress ?? _captureIpAddresses.FirstOrDefault(),
            destinationIpAddress: remoteIpAddress ?? _remoteIpAddress);

        var ethernetFrame = _packetFixtureFactory.CreateEthernetFrameFixture(iPv4Packet);

        var packet = _packetFixtureFactory.CreateCapturedPacketFixture(
            physicalFrame: ethernetFrame,
            networkPacket: iPv4Packet,
            transportSegment: tcpSegment,
            capturedDateTime: capturedDateTime);

        return packet;
    }
}