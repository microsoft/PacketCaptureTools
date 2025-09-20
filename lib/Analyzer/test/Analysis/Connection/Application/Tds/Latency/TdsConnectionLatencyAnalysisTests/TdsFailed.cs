// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using System;
using System.Linq;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Connection.Application.Tds.Latency.TdsConnectionLatencyAnalysisTests;

public partial class TdsConnectionLatencyAnalysisTests
{
    [Fact]
    public void Process_SingleConnectionTdsFailedInTcpHandshake_UpdateFailedTdsConnectionMetrics()
    {
        // Arrange
        var packetTimestamp1 = DateTime.UtcNow.TruncateToSeconds();
        var packetTimestamp2 = packetTimestamp1.Add(TimeSpan.FromSeconds(1));
        var packetTimestamp3 = packetTimestamp2.Add(TimeSpan.FromSeconds(10));
        var packetTimestamp4 = packetTimestamp3.Add(TimeSpan.FromSeconds(20));
        var packetTimestamp5 = packetTimestamp4.Add(TimeSpan.FromSeconds(45));

        var connectionLatency = packetTimestamp5 - packetTimestamp1;
        var lastSuccessfulToLastStateLatency = packetTimestamp5 - packetTimestamp4;

        var packetDataCollection = new[]
        {
            GetPacketData(packetTimestamp1, TdsConnectionState.TcpHandshake),
            GetPacketData(packetTimestamp2, TdsConnectionState.TcpHandshake),
            GetPacketData(packetTimestamp3, TdsConnectionState.TcpHandshake),
            GetPacketData(packetTimestamp4, TdsConnectionState.TcpHandshake),
            GetPacketData(packetTimestamp5, TdsConnectionState.ClosedWithError),
        };

        var expectedTdsConnectionLatencies = new TdsConnectionLatencies
        {
            TdsConnectionState = TdsConnectionState.ClosedWithError,
            LastSuccessfulTdsConnectionState = TdsConnectionState.TcpHandshake,
            LastSuccessfulToLastStateLatency = lastSuccessfulToLastStateLatency,
            LastPacketTimestamp = packetTimestamp5,
            TotalLatency = connectionLatency,
        };

        // Act
        foreach (var packetData in packetDataCollection)
        {
            _sut.Process(packetData.Packet, packetData.Snapshot);
        }

        // Assert
        _sut.TcpHandshakeToPreLoginAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginResponseToClientHelloAverageLatencies.Count.Should().Be(0);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(0);
        _sut.ServerHelloToKeyExchangeAverageLatencies.Count.Should().Be(0);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(0);
        _sut.CipherChangeToLoginMessageAverageLatencies.Count.Should().Be(0);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(1);
        _sut.TdsConnectionLatencies.Count.Should().Be(1);

        _sut.FailedTdsConnectionMetrics.First().Value.First().Should().BeEquivalentTo(expectedTdsConnectionLatencies, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void Process_SingleConnectionTdsFailedAfterPreLogin_UpdateFailedTdsConnectionMetrics()
    {
        // Arrange
        var tcpHandshakeToPreLoginLatency = TimeSpan.FromMinutes(2);
        var tdsFailedLatency = TimeSpan.FromSeconds(10);
        var totalLatency = tcpHandshakeToPreLoginLatency + tdsFailedLatency;

        var tcpHandshakeTimestamp = DateTime.UtcNow.TruncateToSeconds();
        var preLoginTimestamp = tcpHandshakeTimestamp.Add(tcpHandshakeToPreLoginLatency);
        var tdsFailedTimestamp = preLoginTimestamp.Add(tdsFailedLatency);

        var packetDataCollection = new[]
        {
            GetPacketData(tcpHandshakeTimestamp, TdsConnectionState.TcpHandshake),
            GetPacketData(preLoginTimestamp, TdsConnectionState.PreLogin),
            GetPacketData(tdsFailedTimestamp, TdsConnectionState.ClosedWithError),
        };

        var expectedTdsConnectionLatencies = new TdsConnectionLatencies
        {
            TdsConnectionState = TdsConnectionState.ClosedWithError,
            LastSuccessfulTdsConnectionState = TdsConnectionState.PreLogin,
            TcpHandshakeToPreLoginLatency = tcpHandshakeToPreLoginLatency,
            PreLoginToLatestStateLatency = tdsFailedTimestamp - preLoginTimestamp,
            LastSuccessfulToLastStateLatency = tdsFailedLatency,
            LastPacketTimestamp = tdsFailedTimestamp,
            TotalLatency = totalLatency,
        };

        // Act
        foreach (var packetData in packetDataCollection)
        {
            _sut.Process(packetData.Packet, packetData.Snapshot);
        }

        // Assert
        _sut.TcpHandshakeToPreLoginAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginResponseToClientHelloAverageLatencies.Count.Should().Be(0);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(0);
        _sut.ServerHelloToKeyExchangeAverageLatencies.Count.Should().Be(0);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(0);
        _sut.CipherChangeToLoginMessageAverageLatencies.Count.Should().Be(0);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(1);
        _sut.TdsConnectionLatencies.Count.Should().Be(1);

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp].Should().Be(tcpHandshakeToPreLoginLatency);
        _sut.FailedTdsConnectionMetrics.First().Value.First().Should().BeEquivalentTo(expectedTdsConnectionLatencies, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void Process_SingleConnectionTdsFailedAfterPreLoginResponse_UpdateFailedTdsConnectionMetrics()
    {
        // Arrange
        var tcpHandshakeToPreLoginLatency = TimeSpan.FromMinutes(2);
        var preLoginToPreLoginResponseLatency = TimeSpan.FromSeconds(10);
        var tdsFailedLatency = TimeSpan.FromSeconds(10);
        var totalLatency = tcpHandshakeToPreLoginLatency + preLoginToPreLoginResponseLatency + tdsFailedLatency;

        var tcpHandshakeTimestamp = DateTime.UtcNow.TruncateToSeconds();
        var preLoginTimestamp = tcpHandshakeTimestamp.Add(tcpHandshakeToPreLoginLatency);
        var preLoginResponseTimestamp = preLoginTimestamp.Add(preLoginToPreLoginResponseLatency);
        var tdsFailedTimestamp = preLoginResponseTimestamp.Add(tdsFailedLatency);

        var packetDataCollection = new[]
        {
            GetPacketData(tcpHandshakeTimestamp, TdsConnectionState.TcpHandshake),
            GetPacketData(preLoginTimestamp, TdsConnectionState.PreLogin),
            GetPacketData(preLoginResponseTimestamp, TdsConnectionState.PreLoginResponse),
            GetPacketData(tdsFailedTimestamp, TdsConnectionState.ClosedWithError),
        };

        var expectedTdsConnectionLatencies = new TdsConnectionLatencies
        {
            TdsConnectionState = TdsConnectionState.ClosedWithError,
            LastSuccessfulTdsConnectionState = TdsConnectionState.PreLoginResponse,
            TcpHandshakeToPreLoginLatency = tcpHandshakeToPreLoginLatency,
            PreLoginToPreLoginResponseLatency = preLoginToPreLoginResponseLatency,
            PreLoginToLatestStateLatency = tdsFailedTimestamp - preLoginTimestamp,
            LastSuccessfulToLastStateLatency = tdsFailedLatency,
            LastPacketTimestamp = tdsFailedTimestamp,
            TotalLatency = totalLatency,
        };

        // Act
        foreach (var packetData in packetDataCollection)
        {
            _sut.Process(packetData.Packet, packetData.Snapshot);
        }

        // Assert
        _sut.TcpHandshakeToPreLoginAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginResponseToClientHelloAverageLatencies.Count.Should().Be(0);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(0);
        _sut.ServerHelloToKeyExchangeAverageLatencies.Count.Should().Be(0);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(0);
        _sut.CipherChangeToLoginMessageAverageLatencies.Count.Should().Be(0);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(1);
        _sut.TdsConnectionLatencies.Count.Should().Be(1);

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp].Should().Be(tcpHandshakeToPreLoginLatency);
        _sut.PreLoginToPreLoginResponseAverageLatencies[preLoginResponseTimestamp].Should().Be(preLoginToPreLoginResponseLatency);
        _sut.FailedTdsConnectionMetrics.First().Value.First().Should().BeEquivalentTo(expectedTdsConnectionLatencies, options => options.IncludingInternalProperties());
    }


    [Fact]
    public void Process_SingleConnectionTdsFailedAfterClientHello_UpdateFailedTdsConnectionMetrics()
    {
        // Arrange
        var tcpHandshakeToPreLoginLatency = TimeSpan.FromMinutes(2);
        var preLoginToPreLoginResponseLatency = TimeSpan.FromSeconds(10);
        var preLoginResponseToClientHelloLatency = TimeSpan.FromSeconds(20);
        var tdsFailedLatency = TimeSpan.FromSeconds(10);
        var totalLatency = tcpHandshakeToPreLoginLatency + preLoginToPreLoginResponseLatency +
                           preLoginResponseToClientHelloLatency + tdsFailedLatency;

        var tcpHandshakeTimestamp = DateTime.UtcNow.TruncateToSeconds();
        var preLoginTimestamp = tcpHandshakeTimestamp.Add(tcpHandshakeToPreLoginLatency);
        var preLoginResponseTimestamp = preLoginTimestamp.Add(preLoginToPreLoginResponseLatency);
        var clientHelloTimestamp = preLoginResponseTimestamp.Add(preLoginResponseToClientHelloLatency);
        var tdsFailedTimestamp = clientHelloTimestamp.Add(tdsFailedLatency);

        var packetDataCollection = new[]
        {
            GetPacketData(tcpHandshakeTimestamp, TdsConnectionState.TcpHandshake),
            GetPacketData(preLoginTimestamp, TdsConnectionState.PreLogin),
            GetPacketData(preLoginResponseTimestamp, TdsConnectionState.PreLoginResponse),
            GetPacketData(clientHelloTimestamp, TdsConnectionState.ClientHello),
            GetPacketData(tdsFailedTimestamp, TdsConnectionState.ClosedWithError),
        };

        var expectedTdsConnectionLatencies = new TdsConnectionLatencies
        {
            TdsConnectionState = TdsConnectionState.ClosedWithError,
            LastSuccessfulTdsConnectionState = TdsConnectionState.ClientHello,
            TcpHandshakeToPreLoginLatency = tcpHandshakeToPreLoginLatency,
            PreLoginToPreLoginResponseLatency = preLoginToPreLoginResponseLatency,
            PreLoginResponseToClientHelloLatency = preLoginResponseToClientHelloLatency,
            PreLoginToLatestStateLatency = tdsFailedTimestamp - preLoginTimestamp,
            LastSuccessfulToLastStateLatency = tdsFailedLatency,
            LastPacketTimestamp = tdsFailedTimestamp,
            TotalLatency = totalLatency,
        };

        // Act
        foreach (var packetData in packetDataCollection)
        {
            _sut.Process(packetData.Packet, packetData.Snapshot);
        }

        // Assert
        _sut.TcpHandshakeToPreLoginAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginResponseToClientHelloAverageLatencies.Count.Should().Be(1);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(0);
        _sut.ServerHelloToKeyExchangeAverageLatencies.Count.Should().Be(0);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(0);
        _sut.CipherChangeToLoginMessageAverageLatencies.Count.Should().Be(0);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(1);
        _sut.TdsConnectionLatencies.Count.Should().Be(1);

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp].Should().Be(tcpHandshakeToPreLoginLatency);
        _sut.PreLoginToPreLoginResponseAverageLatencies[preLoginResponseTimestamp].Should().Be(preLoginToPreLoginResponseLatency);
        _sut.PreLoginResponseToClientHelloAverageLatencies[clientHelloTimestamp].Should().Be(preLoginResponseToClientHelloLatency);
        _sut.FailedTdsConnectionMetrics.First().Value.First().Should().BeEquivalentTo(expectedTdsConnectionLatencies, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void Process_SingleConnectionTdsFailedAfterServerHello_UpdateFailedTdsConnectionMetrics()
    {
        // Arrange
        var tcpHandshakeToPreLoginLatency = TimeSpan.FromMinutes(2);
        var preLoginToPreLoginResponseLatency = TimeSpan.FromSeconds(10);
        var preLoginResponseToClientHelloLatency = TimeSpan.FromSeconds(20);
        var clientHelloToServerHelloLatency = TimeSpan.FromSeconds(30);
        var tdsFailedLatency = TimeSpan.FromSeconds(10);
        var totalLatency = tcpHandshakeToPreLoginLatency + preLoginToPreLoginResponseLatency +
                           preLoginResponseToClientHelloLatency + clientHelloToServerHelloLatency + tdsFailedLatency;

        var tcpHandshakeTimestamp = DateTime.UtcNow.TruncateToSeconds();
        var preLoginTimestamp = tcpHandshakeTimestamp.Add(tcpHandshakeToPreLoginLatency);
        var preLoginResponseTimestamp = preLoginTimestamp.Add(preLoginToPreLoginResponseLatency);
        var clientHelloTimestamp = preLoginResponseTimestamp.Add(preLoginResponseToClientHelloLatency);
        var serverHelloTimestamp = clientHelloTimestamp.Add(clientHelloToServerHelloLatency);
        var tdsFailedTimestamp = serverHelloTimestamp.Add(tdsFailedLatency);

        var packetDataCollection = new[]
        {
            GetPacketData(tcpHandshakeTimestamp, TdsConnectionState.TcpHandshake),
            GetPacketData(preLoginTimestamp, TdsConnectionState.PreLogin),
            GetPacketData(preLoginResponseTimestamp, TdsConnectionState.PreLoginResponse),
            GetPacketData(clientHelloTimestamp, TdsConnectionState.ClientHello),
            GetPacketData(serverHelloTimestamp, TdsConnectionState.ServerHello),
            GetPacketData(tdsFailedTimestamp, TdsConnectionState.ClosedWithError),
        };

        var expectedTdsConnectionLatencies = new TdsConnectionLatencies
        {
            TdsConnectionState = TdsConnectionState.ClosedWithError,
            LastSuccessfulTdsConnectionState = TdsConnectionState.ServerHello,
            TcpHandshakeToPreLoginLatency = tcpHandshakeToPreLoginLatency,
            PreLoginToPreLoginResponseLatency = preLoginToPreLoginResponseLatency,
            PreLoginResponseToClientHelloLatency = preLoginResponseToClientHelloLatency,
            ClientHelloToServerHelloLatency = clientHelloToServerHelloLatency,
            PreLoginToLatestStateLatency = tdsFailedTimestamp - preLoginTimestamp,
            LastSuccessfulToLastStateLatency = tdsFailedLatency,
            LastPacketTimestamp = tdsFailedTimestamp,
            TotalLatency = totalLatency,
        };

        // Act
        foreach (var packetData in packetDataCollection)
        {
            _sut.Process(packetData.Packet, packetData.Snapshot);
        }

        // Assert
        _sut.TcpHandshakeToPreLoginAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginResponseToClientHelloAverageLatencies.Count.Should().Be(1);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(1);
        _sut.ServerHelloToKeyExchangeAverageLatencies.Count.Should().Be(0);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(0);
        _sut.CipherChangeToLoginMessageAverageLatencies.Count.Should().Be(0);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(1);
        _sut.TdsConnectionLatencies.Count.Should().Be(1);

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp].Should().Be(tcpHandshakeToPreLoginLatency);
        _sut.PreLoginToPreLoginResponseAverageLatencies[preLoginResponseTimestamp].Should().Be(preLoginToPreLoginResponseLatency);
        _sut.PreLoginResponseToClientHelloAverageLatencies[clientHelloTimestamp].Should().Be(preLoginResponseToClientHelloLatency);
        _sut.ClientHelloToServerHelloAverageLatencies[serverHelloTimestamp].Should().Be(clientHelloToServerHelloLatency);
        _sut.FailedTdsConnectionMetrics.First().Value.First().Should().BeEquivalentTo(expectedTdsConnectionLatencies, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void Process_SingleConnectionTdsFailedAfterKeyExchange_UpdateFailedTdsConnectionMetrics()
    {
        // Arrange
        var tcpHandshakeToPreLoginLatency = TimeSpan.FromMinutes(2);
        var preLoginToPreLoginResponseLatency = TimeSpan.FromSeconds(10);
        var preLoginResponseToClientHelloLatency = TimeSpan.FromSeconds(20);
        var clientHelloToServerHelloLatency = TimeSpan.FromSeconds(30);
        var serverHelloToKeyExchangeLatency = TimeSpan.FromSeconds(40);
        var tdsFailedLatency = TimeSpan.FromSeconds(10);
        var totalLatency = tcpHandshakeToPreLoginLatency + preLoginToPreLoginResponseLatency +
                           preLoginResponseToClientHelloLatency + clientHelloToServerHelloLatency + serverHelloToKeyExchangeLatency +
                           tdsFailedLatency;

        var tcpHandshakeTimestamp = DateTime.UtcNow.TruncateToSeconds();
        var preLoginTimestamp = tcpHandshakeTimestamp.Add(tcpHandshakeToPreLoginLatency);
        var preLoginResponseTimestamp = preLoginTimestamp.Add(preLoginToPreLoginResponseLatency);
        var clientHelloTimestamp = preLoginResponseTimestamp.Add(preLoginResponseToClientHelloLatency);
        var serverHelloTimestamp = clientHelloTimestamp.Add(clientHelloToServerHelloLatency);
        var keyExchangeTimestamp = serverHelloTimestamp.Add(serverHelloToKeyExchangeLatency);
        var tdsFailedTimestamp = keyExchangeTimestamp.Add(tdsFailedLatency);

        var packetDataCollection = new[]
        {
            GetPacketData(tcpHandshakeTimestamp, TdsConnectionState.TcpHandshake),
            GetPacketData(preLoginTimestamp, TdsConnectionState.PreLogin),
            GetPacketData(preLoginResponseTimestamp, TdsConnectionState.PreLoginResponse),
            GetPacketData(clientHelloTimestamp, TdsConnectionState.ClientHello),
            GetPacketData(serverHelloTimestamp, TdsConnectionState.ServerHello),
            GetPacketData(keyExchangeTimestamp, TdsConnectionState.KeyExchange),
            GetPacketData(tdsFailedTimestamp, TdsConnectionState.ClosedWithError),
        };

        var expectedTdsConnectionLatencies = new TdsConnectionLatencies
        {
            TdsConnectionState = TdsConnectionState.ClosedWithError,
            LastSuccessfulTdsConnectionState = TdsConnectionState.KeyExchange,
            TcpHandshakeToPreLoginLatency = tcpHandshakeToPreLoginLatency,
            PreLoginToPreLoginResponseLatency = preLoginToPreLoginResponseLatency,
            PreLoginResponseToClientHelloLatency = preLoginResponseToClientHelloLatency,
            ClientHelloToServerHelloLatency = clientHelloToServerHelloLatency,
            ServerHelloToKeyExchangeLatency = serverHelloToKeyExchangeLatency,
            PreLoginToLatestStateLatency = tdsFailedTimestamp - preLoginTimestamp,
            LastSuccessfulToLastStateLatency = tdsFailedLatency,
            LastPacketTimestamp = tdsFailedTimestamp,
            TotalLatency = totalLatency,
        };

        // Act
        foreach (var packetData in packetDataCollection)
        {
            _sut.Process(packetData.Packet, packetData.Snapshot);
        }

        // Assert
        _sut.TcpHandshakeToPreLoginAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginResponseToClientHelloAverageLatencies.Count.Should().Be(1);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(1);
        _sut.ServerHelloToKeyExchangeAverageLatencies.Count.Should().Be(1);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(0);
        _sut.CipherChangeToLoginMessageAverageLatencies.Count.Should().Be(0);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(1);
        _sut.TdsConnectionLatencies.Count.Should().Be(1);

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp].Should().Be(tcpHandshakeToPreLoginLatency);
        _sut.PreLoginToPreLoginResponseAverageLatencies[preLoginResponseTimestamp].Should().Be(preLoginToPreLoginResponseLatency);
        _sut.PreLoginResponseToClientHelloAverageLatencies[clientHelloTimestamp].Should().Be(preLoginResponseToClientHelloLatency);
        _sut.ClientHelloToServerHelloAverageLatencies[serverHelloTimestamp].Should().Be(clientHelloToServerHelloLatency);
        _sut.ServerHelloToKeyExchangeAverageLatencies[keyExchangeTimestamp].Should().Be(serverHelloToKeyExchangeLatency);
        _sut.FailedTdsConnectionMetrics.First().Value.First().Should().BeEquivalentTo(expectedTdsConnectionLatencies, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void Process_SingleConnectionTdsFailedAfterCipherChange_UpdateFailedTdsConnectionMetrics()
    {
        // Arrange
        var tcpHandshakeToPreLoginLatency = TimeSpan.FromMinutes(2);
        var preLoginToPreLoginResponseLatency = TimeSpan.FromSeconds(10);
        var preLoginResponseToClientHelloLatency = TimeSpan.FromSeconds(20);
        var clientHelloToServerHelloLatency = TimeSpan.FromSeconds(30);
        var serverHelloToKeyExchangeLatency = TimeSpan.FromSeconds(40);
        var keyExchangeToCipherChangeLatency = TimeSpan.FromSeconds(50);
        var tdsFailedLatency = TimeSpan.FromSeconds(10);
        var totalLatency = tcpHandshakeToPreLoginLatency + preLoginToPreLoginResponseLatency +
                           preLoginResponseToClientHelloLatency + clientHelloToServerHelloLatency + serverHelloToKeyExchangeLatency +
                           keyExchangeToCipherChangeLatency + tdsFailedLatency;

        var tcpHandshakeTimestamp = DateTime.UtcNow.TruncateToSeconds();
        var preLoginTimestamp = tcpHandshakeTimestamp.Add(tcpHandshakeToPreLoginLatency);
        var preLoginResponseTimestamp = preLoginTimestamp.Add(preLoginToPreLoginResponseLatency);
        var clientHelloTimestamp = preLoginResponseTimestamp.Add(preLoginResponseToClientHelloLatency);
        var serverHelloTimestamp = clientHelloTimestamp.Add(clientHelloToServerHelloLatency);
        var keyExchangeTimestamp = serverHelloTimestamp.Add(serverHelloToKeyExchangeLatency);
        var cipherChangeTimestamp = keyExchangeTimestamp.Add(keyExchangeToCipherChangeLatency);
        var tdsFailedTimestamp = cipherChangeTimestamp.Add(tdsFailedLatency);

        var packetDataCollection = new[]
        {
            GetPacketData(tcpHandshakeTimestamp,TdsConnectionState.TcpHandshake),
            GetPacketData(preLoginTimestamp, TdsConnectionState.PreLogin),
            GetPacketData(preLoginResponseTimestamp, TdsConnectionState.PreLoginResponse),
            GetPacketData(clientHelloTimestamp, TdsConnectionState.ClientHello),
            GetPacketData(serverHelloTimestamp, TdsConnectionState.ServerHello),
            GetPacketData(keyExchangeTimestamp, TdsConnectionState.KeyExchange),
            GetPacketData(cipherChangeTimestamp, TdsConnectionState.CipherChange),
            GetPacketData(tdsFailedTimestamp, TdsConnectionState.ClosedWithError),
        };

        var expectedTdsConnectionLatencies = new TdsConnectionLatencies
        {
            TdsConnectionState = TdsConnectionState.ClosedWithError,
            LastSuccessfulTdsConnectionState = TdsConnectionState.CipherChange,
            TcpHandshakeToPreLoginLatency = tcpHandshakeToPreLoginLatency,
            PreLoginToPreLoginResponseLatency = preLoginToPreLoginResponseLatency,
            PreLoginResponseToClientHelloLatency = preLoginResponseToClientHelloLatency,
            ClientHelloToServerHelloLatency = clientHelloToServerHelloLatency,
            ServerHelloToKeyExchangeLatency = serverHelloToKeyExchangeLatency,
            KeyExchangeToCipherChangeLatency = keyExchangeToCipherChangeLatency,
            PreLoginToLatestStateLatency = tdsFailedTimestamp - preLoginTimestamp,
            LastSuccessfulToLastStateLatency = tdsFailedLatency,
            LastPacketTimestamp = tdsFailedTimestamp,
            TotalLatency = totalLatency,
        };

        // Act
        foreach (var packetData in packetDataCollection)
        {
            _sut.Process(packetData.Packet, packetData.Snapshot);
        }

        // Assert
        _sut.TcpHandshakeToPreLoginAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginResponseToClientHelloAverageLatencies.Count.Should().Be(1);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(1);
        _sut.ServerHelloToKeyExchangeAverageLatencies.Count.Should().Be(1);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(1);
        _sut.CipherChangeToLoginMessageAverageLatencies.Count.Should().Be(0);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(1);
        _sut.TdsConnectionLatencies.Count.Should().Be(1);

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp].Should().Be(tcpHandshakeToPreLoginLatency);
        _sut.PreLoginToPreLoginResponseAverageLatencies[preLoginResponseTimestamp].Should().Be(preLoginToPreLoginResponseLatency);
        _sut.PreLoginResponseToClientHelloAverageLatencies[clientHelloTimestamp].Should().Be(preLoginResponseToClientHelloLatency);
        _sut.ClientHelloToServerHelloAverageLatencies[serverHelloTimestamp].Should().Be(clientHelloToServerHelloLatency);
        _sut.ServerHelloToKeyExchangeAverageLatencies[keyExchangeTimestamp].Should().Be(serverHelloToKeyExchangeLatency);
        _sut.KeyExchangeToCipherChangeAverageLatencies[cipherChangeTimestamp].Should().Be(keyExchangeToCipherChangeLatency);
        _sut.FailedTdsConnectionMetrics.First().Value.First().Should().BeEquivalentTo(expectedTdsConnectionLatencies, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void Process_SingleConnectionTdsFailedAfterLoginMessage_UpdateFailedTdsConnectionMetrics()
    {
        // Arrange
        var tcpHandshakeToPreLoginLatency = TimeSpan.FromMinutes(2);
        var preLoginToPreLoginResponseLatency = TimeSpan.FromSeconds(10);
        var preLoginResponseToClientHelloLatency = TimeSpan.FromSeconds(20);
        var clientHelloToServerHelloLatency = TimeSpan.FromSeconds(30);
        var serverHelloToKeyExchangeLatency = TimeSpan.FromSeconds(40);
        var keyExchangeToCipherChangeLatency = TimeSpan.FromSeconds(50);
        var cipherChangeToLoginMessageLatency = TimeSpan.FromSeconds(60);
        var tdsFailedLatency = TimeSpan.FromSeconds(10);
        var totalLatency = tcpHandshakeToPreLoginLatency + preLoginToPreLoginResponseLatency +
                           preLoginResponseToClientHelloLatency + clientHelloToServerHelloLatency + serverHelloToKeyExchangeLatency +
                           keyExchangeToCipherChangeLatency + cipherChangeToLoginMessageLatency + tdsFailedLatency;

        var tcpHandshakeTimestamp = DateTime.UtcNow.TruncateToSeconds();
        var preLoginTimestamp = tcpHandshakeTimestamp.Add(tcpHandshakeToPreLoginLatency);
        var preLoginResponseTimestamp = preLoginTimestamp.Add(preLoginToPreLoginResponseLatency);
        var clientHelloTimestamp = preLoginResponseTimestamp.Add(preLoginResponseToClientHelloLatency);
        var serverHelloTimestamp = clientHelloTimestamp.Add(clientHelloToServerHelloLatency);
        var keyExchangeTimestamp = serverHelloTimestamp.Add(serverHelloToKeyExchangeLatency);
        var cipherChangeTimestamp = keyExchangeTimestamp.Add(keyExchangeToCipherChangeLatency);
        var loginMessageTimestamp = cipherChangeTimestamp.Add(cipherChangeToLoginMessageLatency);
        var tdsFailedTimestamp = loginMessageTimestamp.Add(tdsFailedLatency);

        var packetDataCollection = new[]
        {
            GetPacketData(tcpHandshakeTimestamp, TdsConnectionState.TcpHandshake),
            GetPacketData(preLoginTimestamp, TdsConnectionState.PreLogin),
            GetPacketData(preLoginResponseTimestamp, TdsConnectionState.PreLoginResponse),
            GetPacketData(clientHelloTimestamp, TdsConnectionState.ClientHello),
            GetPacketData(serverHelloTimestamp, TdsConnectionState.ServerHello),
            GetPacketData(keyExchangeTimestamp, TdsConnectionState.KeyExchange),
            GetPacketData(cipherChangeTimestamp, TdsConnectionState.CipherChange),
            GetPacketData(loginMessageTimestamp, TdsConnectionState.LoginMessage),
            GetPacketData(tdsFailedTimestamp, TdsConnectionState.ClosedWithError),
        };

        var expectedTdsConnectionLatencies = new TdsConnectionLatencies
        {
            TdsConnectionState = TdsConnectionState.ClosedWithError,
            LastSuccessfulTdsConnectionState = TdsConnectionState.LoginMessage,
            TcpHandshakeToPreLoginLatency = tcpHandshakeToPreLoginLatency,
            PreLoginToPreLoginResponseLatency = preLoginToPreLoginResponseLatency,
            PreLoginResponseToClientHelloLatency = preLoginResponseToClientHelloLatency,
            ClientHelloToServerHelloLatency = clientHelloToServerHelloLatency,
            ServerHelloToKeyExchangeLatency = serverHelloToKeyExchangeLatency,
            KeyExchangeToCipherChangeLatency = keyExchangeToCipherChangeLatency,
            CipherChangeToLoginMessageLatency = cipherChangeToLoginMessageLatency,
            PreLoginToLatestStateLatency = tdsFailedTimestamp - preLoginTimestamp,
            LastSuccessfulToLastStateLatency = tdsFailedLatency,
            LastPacketTimestamp = tdsFailedTimestamp,
            TotalLatency = totalLatency,
        };

        // Act
        foreach (var packetData in packetDataCollection)
        {
            _sut.Process(packetData.Packet, packetData.Snapshot);
        }

        // Assert
        _sut.TcpHandshakeToPreLoginAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginResponseToClientHelloAverageLatencies.Count.Should().Be(1);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(1);
        _sut.ServerHelloToKeyExchangeAverageLatencies.Count.Should().Be(1);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(1);
        _sut.CipherChangeToLoginMessageAverageLatencies.Count.Should().Be(1);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(1);
        _sut.TdsConnectionLatencies.Count.Should().Be(1);

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp].Should().Be(tcpHandshakeToPreLoginLatency);
        _sut.PreLoginToPreLoginResponseAverageLatencies[preLoginResponseTimestamp].Should().Be(preLoginToPreLoginResponseLatency);
        _sut.PreLoginResponseToClientHelloAverageLatencies[clientHelloTimestamp].Should().Be(preLoginResponseToClientHelloLatency);
        _sut.ClientHelloToServerHelloAverageLatencies[serverHelloTimestamp].Should().Be(clientHelloToServerHelloLatency);
        _sut.ServerHelloToKeyExchangeAverageLatencies[keyExchangeTimestamp].Should().Be(serverHelloToKeyExchangeLatency);
        _sut.KeyExchangeToCipherChangeAverageLatencies[cipherChangeTimestamp].Should().Be(keyExchangeToCipherChangeLatency);
        _sut.CipherChangeToLoginMessageAverageLatencies[loginMessageTimestamp].Should().Be(cipherChangeToLoginMessageLatency);
        _sut.FailedTdsConnectionMetrics.First().Value.First().Should().BeEquivalentTo(expectedTdsConnectionLatencies, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void Process_SingleConnectionTdsFailedAfterLoginAck_UpdateAverageMetricsDoNotUpdateFailedTdsConnectionMetrics()
    {
        // Arrange
        var tcpHandshakeToPreLoginLatency = TimeSpan.FromMinutes(2);
        var preLoginToPreLoginResponseLatency = TimeSpan.FromSeconds(10);
        var preLoginResponseToClientHelloLatency = TimeSpan.FromSeconds(20);
        var clientHelloToServerHelloLatency = TimeSpan.FromSeconds(30);
        var serverHelloToKeyExchangeLatency = TimeSpan.FromSeconds(40);
        var keyExchangeToCipherChangeLatency = TimeSpan.FromSeconds(50);
        var cipherChangeToLoginMessageLatency = TimeSpan.FromSeconds(60);
        var loginMessageToLoginAckLatency = TimeSpan.FromSeconds(70);
        var tdsFailedLatency = TimeSpan.FromSeconds(10);

        var tcpHandshakeTimestamp = DateTime.UtcNow.TruncateToSeconds();
        var preLoginTimestamp = tcpHandshakeTimestamp.Add(tcpHandshakeToPreLoginLatency);
        var preLoginResponseTimestamp = preLoginTimestamp.Add(preLoginToPreLoginResponseLatency);
        var clientHelloTimestamp = preLoginResponseTimestamp.Add(preLoginResponseToClientHelloLatency);
        var serverHelloTimestamp = clientHelloTimestamp.Add(clientHelloToServerHelloLatency);
        var keyExchangeTimestamp = serverHelloTimestamp.Add(serverHelloToKeyExchangeLatency);
        var cipherChangeTimestamp = keyExchangeTimestamp.Add(keyExchangeToCipherChangeLatency);
        var loginMessageTimestamp = cipherChangeTimestamp.Add(cipherChangeToLoginMessageLatency);
        var loginAckTimestamp = loginMessageTimestamp.Add(loginMessageToLoginAckLatency);
        var tdsFailedTimestamp = loginMessageTimestamp.Add(tdsFailedLatency);

        var packetDataCollection = new[]
        {
            GetPacketData(tcpHandshakeTimestamp, TdsConnectionState.TcpHandshake),
            GetPacketData(preLoginTimestamp, TdsConnectionState.PreLogin),
            GetPacketData(preLoginResponseTimestamp, TdsConnectionState.PreLoginResponse),
            GetPacketData(clientHelloTimestamp, TdsConnectionState.ClientHello),
            GetPacketData(serverHelloTimestamp, TdsConnectionState.ServerHello),
            GetPacketData(keyExchangeTimestamp, TdsConnectionState.KeyExchange),
            GetPacketData(cipherChangeTimestamp, TdsConnectionState.CipherChange),
            GetPacketData(loginMessageTimestamp, TdsConnectionState.LoginMessage),
            GetPacketData(loginAckTimestamp, TdsConnectionState.LoginAck),
            GetPacketData(tdsFailedTimestamp, TdsConnectionState.ConnectionClosedAfterLoginAckTdsState),
        };

        // Act
        foreach (var packetData in packetDataCollection)
        {
            _sut.Process(packetData.Packet, packetData.Snapshot);
        }

        // Assert
        _sut.TcpHandshakeToPreLoginAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginResponseToClientHelloAverageLatencies.Count.Should().Be(1);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(1);
        _sut.ServerHelloToKeyExchangeAverageLatencies.Count.Should().Be(1);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(1);
        _sut.CipherChangeToLoginMessageAverageLatencies.Count.Should().Be(1);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(1);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(1);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(0);
        _sut.TdsConnectionLatencies.Count.Should().Be(1);

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp].Should().Be(tcpHandshakeToPreLoginLatency);
        _sut.PreLoginToPreLoginResponseAverageLatencies[preLoginResponseTimestamp].Should().Be(preLoginToPreLoginResponseLatency);
        _sut.PreLoginResponseToClientHelloAverageLatencies[clientHelloTimestamp].Should().Be(preLoginResponseToClientHelloLatency);
        _sut.ClientHelloToServerHelloAverageLatencies[serverHelloTimestamp].Should().Be(clientHelloToServerHelloLatency);
        _sut.ServerHelloToKeyExchangeAverageLatencies[keyExchangeTimestamp].Should().Be(serverHelloToKeyExchangeLatency);
        _sut.KeyExchangeToCipherChangeAverageLatencies[cipherChangeTimestamp].Should().Be(keyExchangeToCipherChangeLatency);
        _sut.CipherChangeToLoginMessageAverageLatencies[loginMessageTimestamp].Should().Be(cipherChangeToLoginMessageLatency);
        _sut.LoginMessageToLoginAckAverageLatencies[loginAckTimestamp].Should().Be(loginMessageToLoginAckLatency);
        _sut.PreLoginToLoginAckAverageLatencies[loginAckTimestamp].Should().Be(loginAckTimestamp - preLoginTimestamp);
    }

    [Theory]
    [InlineData(TcpConnectionState.Established, TdsConnectionState.PreLogin)]
    [InlineData(TcpConnectionState.Established, TdsConnectionState.PreLoginResponse)]
    [InlineData(TcpConnectionState.Established, TdsConnectionState.ClientHello)]
    [InlineData(TcpConnectionState.Established, TdsConnectionState.ServerHello)]
    [InlineData(TcpConnectionState.Established, TdsConnectionState.KeyExchange)]
    [InlineData(TcpConnectionState.Established, TdsConnectionState.CipherChange)]
    [InlineData(TcpConnectionState.Established, TdsConnectionState.LoginMessage)]
    [InlineData(TcpConnectionState.AssumedEstablished, TdsConnectionState.PreLogin)]
    [InlineData(TcpConnectionState.AssumedEstablished, TdsConnectionState.PreLoginResponse)]
    [InlineData(TcpConnectionState.AssumedEstablished, TdsConnectionState.ClientHello)]
    [InlineData(TcpConnectionState.AssumedEstablished, TdsConnectionState.ServerHello)]
    [InlineData(TcpConnectionState.AssumedEstablished, TdsConnectionState.KeyExchange)]
    [InlineData(TcpConnectionState.AssumedEstablished, TdsConnectionState.CipherChange)]
    [InlineData(TcpConnectionState.AssumedEstablished, TdsConnectionState.LoginMessage)]
    public void Process_FirstConnectionInstanceFailedConectionTcpConnectionEstablished_UpdateFailedTdsConnectionMetrics(
        TcpConnectionState tcpConnectionState,
        TdsConnectionState tdsConnectionState)
    {
        // Arrange
        var timestamp = DateTime.UtcNow;

        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(capturedDateTime: timestamp);
        var tdsConnectionSnapshot = GetTdsConnectionSnapshot(
            tdsConnectionState: tdsConnectionState,
            tcpConnectionState: tcpConnectionState);

        // Act
        _sut.Process(capturedPacket, tdsConnectionSnapshot);

        // Assert
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(0);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(0);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(0);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(1);
        _sut.TdsConnectionLatencies.Count.Should().Be(1);
    }
}