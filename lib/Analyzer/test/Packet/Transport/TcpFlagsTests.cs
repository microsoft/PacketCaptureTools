// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Packet.Transport;

public class TcpFlagsTests
{
    [Theory]
    //            NS    CWR    ECE    URG    ACK    PSH    RST    SYN    FIN  bitValue
    [InlineData(true, false, false, false, false, false, false, false, false, 0x100)]
    [InlineData(false, true, false, false, false, false, false, false, false, 0x80)]
    [InlineData(false, false, true, false, false, false, false, false, false, 0x40)]
    [InlineData(false, false, false, true, false, false, false, false, false, 0x20)]
    [InlineData(false, false, false, false, true, false, false, false, false, 0x10)]
    [InlineData(false, false, false, false, false, true, false, false, false, 0x8)]
    [InlineData(false, false, false, false, false, false, true, false, false, 0x4)]
    [InlineData(false, false, false, false, false, false, false, true, false, 0x2)]
    [InlineData(false, false, false, false, false, false, false, false, true, 0x1)]
    [InlineData(false, false, false, false, true, false, false, false, true, 0x11)]
    [InlineData(false, false, false, false, true, true, false, false, false, 0x18)]
    [InlineData(true, true, false, true, true, false, false, false, false, 0x1B0)]
    public void TcpFlags_BitValueConstructor(
        bool ns,
        bool cwr,
        bool ece,
        bool urg,
        bool ack,
        bool psh,
        bool rst,
        bool syn,
        bool fin,
        int bitValue)
    {
        // Arrange
        // Act
        var tcpFlags = new TcpFlags(bitValue);

        // Assert
        tcpFlags.Ns.Should().Be(ns);
        tcpFlags.Cwr.Should().Be(cwr);
        tcpFlags.Ece.Should().Be(ece);
        tcpFlags.Urg.Should().Be(urg);
        tcpFlags.Ack.Should().Be(ack);
        tcpFlags.Psh.Should().Be(psh);
        tcpFlags.Rst.Should().Be(rst);
        tcpFlags.Syn.Should().Be(syn);
        tcpFlags.Fin.Should().Be(fin);
    }

    [Theory]
    //            NS    CWR    ECE    URG    ACK    PSH    RST    SYN    FIN
    [InlineData(true, false, false, false, false, false, false, false, false)]
    [InlineData(false, true, false, false, false, false, false, false, false)]
    [InlineData(false, false, true, false, false, false, false, false, false)]
    [InlineData(false, false, false, true, false, false, false, false, false)]
    [InlineData(false, false, false, false, true, false, false, false, false)]
    [InlineData(false, false, false, false, false, true, false, false, false)]
    [InlineData(false, false, false, false, false, false, true, false, false)]
    [InlineData(false, false, false, false, false, false, false, true, false)]
    [InlineData(false, false, false, false, false, false, false, false, true)]
    [InlineData(false, false, false, false, true, false, false, false, true)]
    [InlineData(false, false, false, false, true, true, false, false, false)]
    [InlineData(true, true, false, true, true, false, false, false, false)]
    public void TcpFlags_FlagsConstructor(
        bool ns,
        bool cwr,
        bool ece,
        bool urg,
        bool ack,
        bool psh,
        bool rst,
        bool syn,
        bool fin)
    {
        // Arrange
        // Act
        var tcpFlags = new TcpFlags(ns: ns, cwr: cwr, ece: ece, urg: urg, ack: ack, psh: psh, rst: rst, syn: syn, fin: fin);

        // Assert
        tcpFlags.Ns.Should().Be(ns);
        tcpFlags.Cwr.Should().Be(cwr);
        tcpFlags.Ece.Should().Be(ece);
        tcpFlags.Urg.Should().Be(urg);
        tcpFlags.Ack.Should().Be(ack);
        tcpFlags.Psh.Should().Be(psh);
        tcpFlags.Rst.Should().Be(rst);
        tcpFlags.Syn.Should().Be(syn);
        tcpFlags.Fin.Should().Be(fin);
    }
}