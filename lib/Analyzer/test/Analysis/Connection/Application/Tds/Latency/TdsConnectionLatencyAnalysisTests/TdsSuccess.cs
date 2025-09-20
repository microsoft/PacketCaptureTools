// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Connection.Application.Tds.Latency.TdsConnectionLatencyAnalysisTests;

public partial class TdsConnectionLatencyAnalysisTests
{
    [Fact]
    public void Process_SingleConnectionLoginComplete_AverageLatenciesShouldBeSingleConnectionLatencies()
    {
        // Arrange
        var tcpHandshakeLatency = TimeSpan.FromMinutes(10);
        var tcpHandshakeSuccessToPreLoginToPreLoginLatency = TimeSpan.FromMinutes(2);
        var preLoginToPreLoginResponseLatency = TimeSpan.FromSeconds(10);
        var preLoginResponseToClientHelloLatency = TimeSpan.FromSeconds(20);
        var clientHelloToServerHelloLatency = TimeSpan.FromSeconds(30);
        var serverHelloToKeyExchangeLatency = TimeSpan.FromSeconds(40);
        var keyExchangeToCipherChangeLatency = TimeSpan.FromSeconds(50);
        var cipherChangeToLoginMessageLatency = TimeSpan.FromSeconds(60);
        var loginMessageToLoginAckLatency = TimeSpan.FromSeconds(70);

        var firstSynTimestamp = DateTime.UtcNow.TruncateToSeconds();
        var tcpEstablishedTimestamp = firstSynTimestamp.Add(tcpHandshakeLatency);
        var preLoginTimestamp = tcpEstablishedTimestamp.Add(tcpHandshakeSuccessToPreLoginToPreLoginLatency);
        var preLoginResponseTimestamp = preLoginTimestamp.Add(preLoginToPreLoginResponseLatency);
        var clientHelloTimestamp = preLoginResponseTimestamp.Add(preLoginResponseToClientHelloLatency);
        var serverHelloTimestamp = clientHelloTimestamp.Add(clientHelloToServerHelloLatency);
        var keyExchangeTimestamp = serverHelloTimestamp.Add(serverHelloToKeyExchangeLatency);
        var cipherChangeTimestamp = keyExchangeTimestamp.Add(keyExchangeToCipherChangeLatency);
        var loginMessageTimestamp = cipherChangeTimestamp.Add(cipherChangeToLoginMessageLatency);
        var loginAckTimestamp = loginMessageTimestamp.Add(loginMessageToLoginAckLatency);

        var packetDataCollection = new[]
        {
            GetPacketData(
                timestamp: tcpEstablishedTimestamp,
                tdsConnectionState: TdsConnectionState.TcpHandshake,
                firstSynTimestamp: firstSynTimestamp,
                establishedTimestamp: tcpEstablishedTimestamp),

            GetPacketData(preLoginTimestamp, TdsConnectionState.PreLogin),
            GetPacketData(preLoginResponseTimestamp, TdsConnectionState.PreLoginResponse),
            GetPacketData(clientHelloTimestamp, TdsConnectionState.ClientHello),
            GetPacketData(serverHelloTimestamp, TdsConnectionState.ServerHello),
            GetPacketData(keyExchangeTimestamp, TdsConnectionState.KeyExchange),
            GetPacketData(cipherChangeTimestamp, TdsConnectionState.CipherChange),
            GetPacketData(loginMessageTimestamp, TdsConnectionState.LoginMessage),
            GetPacketData(loginAckTimestamp, TdsConnectionState.LoginAck),
        };

        var expectedPreLoginToLoginAckAverageLatency = loginAckTimestamp - preLoginTimestamp;

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

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp].Should().Be(tcpHandshakeSuccessToPreLoginToPreLoginLatency);
        _sut.PreLoginToPreLoginResponseAverageLatencies[preLoginResponseTimestamp].Should().Be(preLoginToPreLoginResponseLatency);
        _sut.PreLoginResponseToClientHelloAverageLatencies[clientHelloTimestamp].Should().Be(preLoginResponseToClientHelloLatency);
        _sut.ClientHelloToServerHelloAverageLatencies[serverHelloTimestamp].Should().Be(clientHelloToServerHelloLatency);
        _sut.ServerHelloToKeyExchangeAverageLatencies[keyExchangeTimestamp].Should().Be(serverHelloToKeyExchangeLatency);
        _sut.KeyExchangeToCipherChangeAverageLatencies[cipherChangeTimestamp].Should().Be(keyExchangeToCipherChangeLatency);
        _sut.CipherChangeToLoginMessageAverageLatencies[loginMessageTimestamp].Should().Be(cipherChangeToLoginMessageLatency);
        _sut.LoginMessageToLoginAckAverageLatencies[loginAckTimestamp].Should().Be(loginMessageToLoginAckLatency);
        _sut.PreLoginToLoginAckAverageLatencies[loginAckTimestamp].Should().Be(expectedPreLoginToLoginAckAverageLatency);
    }

    [Fact]
    public void Process_SingleConnectionLoginCompleteWithMultiplePacketsPerState_AverageLatenciesShouldBeSingleConnectionLatencies()
    {
        // Arrange
        var tcpHandshakeLatency = TimeSpan.FromMinutes(10);
        var tcpHandshakeSuccessToPreLoginLatency = TimeSpan.FromMinutes(2);
        var preLoginToPreLoginResponseLatency = TimeSpan.FromSeconds(10);
        var preLoginResponseToClientHelloLatency = TimeSpan.FromSeconds(20);
        var clientHelloToServerHelloLatency = TimeSpan.FromSeconds(30);
        var serverHelloToKeyExchangeLatency = TimeSpan.FromSeconds(40);
        var keyExchangeToCipherChangeLatency = TimeSpan.FromSeconds(50);
        var cipherChangeToLoginMessageLatency = TimeSpan.FromSeconds(60);
        var loginMessageToLoginAckLatency = TimeSpan.FromSeconds(70);

        var firstSynTimestamp = DateTime.UtcNow.TruncateToSeconds();

        var tcpEstablishedTimestamp1 = firstSynTimestamp;
        var tcpEstablishedTimestamp2 = tcpEstablishedTimestamp1.Add(tcpHandshakeLatency);
        var tcpEstablishedTimestamp3 = tcpEstablishedTimestamp2.Add(tcpHandshakeLatency);

        var preLoginTimestamp1 = tcpEstablishedTimestamp3.Add(tcpHandshakeSuccessToPreLoginLatency);
        var preLoginTimestamp2 = preLoginTimestamp1.Add(tcpHandshakeSuccessToPreLoginLatency);
        var preLoginTimestamp3 = preLoginTimestamp2.Add(tcpHandshakeSuccessToPreLoginLatency);

        var preLoginResponseTimestamp1 = preLoginTimestamp3.Add(preLoginToPreLoginResponseLatency);
        var preLoginResponseTimestamp2 = preLoginResponseTimestamp1.Add(preLoginToPreLoginResponseLatency);
        var preLoginResponseTimestamp3 = preLoginResponseTimestamp2.Add(preLoginToPreLoginResponseLatency);

        var clientHelloTimestamp1 = preLoginResponseTimestamp3.Add(preLoginResponseToClientHelloLatency);
        var clientHelloTimestamp2 = clientHelloTimestamp1.Add(preLoginResponseToClientHelloLatency);
        var clientHelloTimestamp3 = clientHelloTimestamp2.Add(preLoginResponseToClientHelloLatency);

        var serverHelloTimestamp1 = clientHelloTimestamp3.Add(clientHelloToServerHelloLatency);
        var serverHelloTimestamp2 = serverHelloTimestamp1.Add(clientHelloToServerHelloLatency);
        var serverHelloTimestamp3 = serverHelloTimestamp2.Add(clientHelloToServerHelloLatency);

        var keyExchangeTimestamp1 = serverHelloTimestamp3.Add(serverHelloToKeyExchangeLatency);
        var keyExchangeTimestamp2 = keyExchangeTimestamp1.Add(serverHelloToKeyExchangeLatency);
        var keyExchangeTimestamp3 = keyExchangeTimestamp2.Add(serverHelloToKeyExchangeLatency);

        var cipherChangeTimestamp1 = keyExchangeTimestamp3.Add(keyExchangeToCipherChangeLatency);
        var cipherChangeTimestamp2 = cipherChangeTimestamp1.Add(keyExchangeToCipherChangeLatency);
        var cipherChangeTimestamp3 = cipherChangeTimestamp2.Add(keyExchangeToCipherChangeLatency);

        var loginMessageTimestamp1 = cipherChangeTimestamp3.Add(cipherChangeToLoginMessageLatency);
        var loginMessageTimestamp2 = loginMessageTimestamp1.Add(cipherChangeToLoginMessageLatency);
        var loginMessageTimestamp3 = loginMessageTimestamp2.Add(cipherChangeToLoginMessageLatency);

        var loginAckTimestamp1 = loginMessageTimestamp3.Add(loginMessageToLoginAckLatency);
        var loginAckTimestamp2 = loginAckTimestamp1.Add(loginMessageToLoginAckLatency);
        var loginAckTimestamp3 = loginAckTimestamp2.Add(loginMessageToLoginAckLatency);

        var expectedTcpEstablishedToPreLoginLatency = preLoginTimestamp1 - tcpEstablishedTimestamp1;
        var expectedPreLoginToPreLoginResponseLatency = preLoginResponseTimestamp1 - preLoginTimestamp1;
        var expectedPreLoginResponseToClientHelloLatency = clientHelloTimestamp1 - preLoginResponseTimestamp1;
        var expectedClientHelloToServerHelloLatency = serverHelloTimestamp1 - clientHelloTimestamp1;
        var expectedServerHelloToKeyExchangeLatency = keyExchangeTimestamp1- serverHelloTimestamp1;
        var expectedKeyExchangeToCipherChangeLatency = cipherChangeTimestamp1 - keyExchangeTimestamp1;
        var expectedCipherChangeToLoginMessageLatency = loginMessageTimestamp1- cipherChangeTimestamp1;
        var expectedLoginMessageToLoginAckLatency = loginAckTimestamp1 - loginMessageTimestamp1;
        var expectedPreLoginToLoginAckAverageLatency = loginAckTimestamp1 - preLoginTimestamp1;
        var expectedTotalLatency = loginAckTimestamp3 - firstSynTimestamp;

        var packetDataCollection = new[]
        {
            GetPacketData(tcpEstablishedTimestamp1, TdsConnectionState.TcpHandshake),
            GetPacketData(tcpEstablishedTimestamp2, TdsConnectionState.TcpHandshake),
            GetPacketData(tcpEstablishedTimestamp3, TdsConnectionState.TcpHandshake),

            GetPacketData(preLoginTimestamp1, TdsConnectionState.PreLogin),
            GetPacketData(preLoginTimestamp2, TdsConnectionState.PreLogin),
            GetPacketData(preLoginTimestamp3, TdsConnectionState.PreLogin),

            GetPacketData(preLoginResponseTimestamp1, TdsConnectionState.PreLoginResponse),
            GetPacketData(preLoginResponseTimestamp2, TdsConnectionState.PreLoginResponse),
            GetPacketData(preLoginResponseTimestamp3, TdsConnectionState.PreLoginResponse),

            GetPacketData(clientHelloTimestamp1, TdsConnectionState.ClientHello),
            GetPacketData(clientHelloTimestamp2, TdsConnectionState.ClientHello),
            GetPacketData(clientHelloTimestamp3, TdsConnectionState.ClientHello),

            GetPacketData(serverHelloTimestamp1, TdsConnectionState.ServerHello),
            GetPacketData(serverHelloTimestamp2, TdsConnectionState.ServerHello),
            GetPacketData(serverHelloTimestamp3, TdsConnectionState.ServerHello),

            GetPacketData(keyExchangeTimestamp1, TdsConnectionState.KeyExchange),
            GetPacketData(keyExchangeTimestamp2, TdsConnectionState.KeyExchange),
            GetPacketData(keyExchangeTimestamp3, TdsConnectionState.KeyExchange),

            GetPacketData(cipherChangeTimestamp1, TdsConnectionState.CipherChange),
            GetPacketData(cipherChangeTimestamp2, TdsConnectionState.CipherChange),
            GetPacketData(cipherChangeTimestamp3, TdsConnectionState.CipherChange),

            GetPacketData(loginMessageTimestamp1, TdsConnectionState.LoginMessage),
            GetPacketData(loginMessageTimestamp2, TdsConnectionState.LoginMessage),
            GetPacketData(loginMessageTimestamp3, TdsConnectionState.LoginMessage),

            GetPacketData(loginAckTimestamp1, TdsConnectionState.LoginAck),
            GetPacketData(loginAckTimestamp2, TdsConnectionState.LoginAck),
            GetPacketData(loginAckTimestamp3, TdsConnectionState.LoginAck),
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

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp1].Should().Be(expectedTcpEstablishedToPreLoginLatency);
        _sut.PreLoginToPreLoginResponseAverageLatencies[preLoginResponseTimestamp1].Should().Be(expectedPreLoginToPreLoginResponseLatency);
        _sut.PreLoginResponseToClientHelloAverageLatencies[clientHelloTimestamp1].Should().Be(expectedPreLoginResponseToClientHelloLatency);
        _sut.ClientHelloToServerHelloAverageLatencies[serverHelloTimestamp1].Should().Be(expectedClientHelloToServerHelloLatency);
        _sut.ServerHelloToKeyExchangeAverageLatencies[keyExchangeTimestamp1].Should().Be(expectedServerHelloToKeyExchangeLatency);
        _sut.KeyExchangeToCipherChangeAverageLatencies[cipherChangeTimestamp1].Should().Be(expectedKeyExchangeToCipherChangeLatency);
        _sut.CipherChangeToLoginMessageAverageLatencies[loginMessageTimestamp1].Should().Be(expectedCipherChangeToLoginMessageLatency);
        _sut.LoginMessageToLoginAckAverageLatencies[loginAckTimestamp1].Should().Be(expectedLoginMessageToLoginAckLatency);
        _sut.PreLoginToLoginAckAverageLatencies[loginAckTimestamp1].Should().Be(expectedPreLoginToLoginAckAverageLatency);
        _sut.TdsConnectionLatencies[loginAckTimestamp3].Should().Be(expectedTotalLatency);
    }

    [Fact]
    public void Process_MultipleConnectionsLoginComplete_AverageLatenciesShouldBeAverageLatencies()
    {
        // Arrange
        var tcpHandshakeLatency1 = TimeSpan.FromMinutes(10);
        var tcpHandshakeSuccessToPreLoginToPreLoginLatency1 = TimeSpan.FromMinutes(2);
        var preLoginToPreLoginResponseLatency1 = TimeSpan.FromSeconds(10);
        var preLoginResponseToClientHelloLatency1 = TimeSpan.FromSeconds(20);
        var clientHelloToServerHelloLatency1 = TimeSpan.FromSeconds(30);
        var serverHelloToKeyExchangeLatency1 = TimeSpan.FromSeconds(40);
        var keyExchangeToCipherChangeLatency1 = TimeSpan.FromSeconds(50);
        var cipherChangeToLoginMessageLatency1 = TimeSpan.FromSeconds(60);
        var loginMessageToLoginAckLatency1 = TimeSpan.FromSeconds(70);

        var firstSynTimestamp1 = DateTime.UtcNow.TruncateToSeconds();
        var tcpEstablishedTimestamp1 = firstSynTimestamp1.Add(tcpHandshakeLatency1);
        var preLoginTimestamp1 = tcpEstablishedTimestamp1.Add(tcpHandshakeSuccessToPreLoginToPreLoginLatency1);
        var preLoginResponseTimestamp1 = preLoginTimestamp1.Add(preLoginToPreLoginResponseLatency1);
        var clientHelloTimestamp1 = preLoginResponseTimestamp1.Add(preLoginResponseToClientHelloLatency1);
        var serverHelloTimestamp1 = clientHelloTimestamp1.Add(clientHelloToServerHelloLatency1);
        var keyExchangeTimestamp1 = serverHelloTimestamp1.Add(serverHelloToKeyExchangeLatency1);
        var cipherChangeTimestamp1 = keyExchangeTimestamp1.Add(keyExchangeToCipherChangeLatency1);
        var loginMessageTimestamp1 = cipherChangeTimestamp1.Add(cipherChangeToLoginMessageLatency1);
        var loginAckTimestamp1 = loginMessageTimestamp1.Add(loginMessageToLoginAckLatency1);

        var tcpHandshakeLatency2 = TimeSpan.FromMinutes(20);
        var tcpHandshakeSuccessToPreLoginToPreLoginLatency2 = TimeSpan.FromMinutes(5);
        var preLoginToPreLoginResponseLatency2 = TimeSpan.FromSeconds(5);
        var preLoginResponseToClientHelloLatency2 = TimeSpan.FromSeconds(15);
        var clientHelloToServerHelloLatency2 = TimeSpan.FromSeconds(25);
        var serverHelloToKeyExchangeLatency2 = TimeSpan.FromSeconds(35);
        var keyExchangeToCipherChangeLatency2 = TimeSpan.FromSeconds(45);
        var cipherChangeToLoginMessageLatency2 = TimeSpan.FromSeconds(55);
        var loginMessageToLoginAckLatency2 = TimeSpan.FromSeconds(65);

        var firstSynTimestamp2 = tcpEstablishedTimestamp1.Add(-tcpHandshakeLatency2);
        var tcpEstablishedTimestamp2 = tcpEstablishedTimestamp1;
        var preLoginTimestamp2 = preLoginResponseTimestamp1.Add(-preLoginToPreLoginResponseLatency2);
        var preLoginResponseTimestamp2 = preLoginResponseTimestamp1;
        var clientHelloTimestamp2 = serverHelloTimestamp1.Add(-clientHelloToServerHelloLatency2);
        var serverHelloTimestamp2 = serverHelloTimestamp1;
        var keyExchangeTimestamp2 = cipherChangeTimestamp1.Add(-keyExchangeToCipherChangeLatency2);
        var cipherChangeTimestamp2 = cipherChangeTimestamp1;
        var loginMessageTimestamp2 = loginAckTimestamp1.Add(-loginMessageToLoginAckLatency2);
        var loginAckTimestamp2 = loginAckTimestamp1;

        var firstSynTimestamp3 = firstSynTimestamp1;
        var tcpEstablishedTimestamp3 = preLoginTimestamp1.Add(-tcpHandshakeSuccessToPreLoginToPreLoginLatency2);
        var preLoginTimestamp3 = preLoginTimestamp1;
        var preLoginResponseTimestamp3 = clientHelloTimestamp1.Add(-preLoginResponseToClientHelloLatency2);
        var clientHelloTimestamp3 = clientHelloTimestamp1;
        var serverHelloTimestamp3 = keyExchangeTimestamp1.Add(-serverHelloToKeyExchangeLatency2);
        var keyExchangeTimestamp3 = keyExchangeTimestamp1;
        var cipherChangeTimestamp3 = loginMessageTimestamp1.Add(-cipherChangeToLoginMessageLatency2);
        var loginMessageTimestamp3 = loginMessageTimestamp1;
        var loginAckTimestamp3 = loginMessageTimestamp1.Add(clientHelloToServerHelloLatency2);

        var packetDataCollection = new[]
        {
            GetPacketData(
                timestamp: tcpEstablishedTimestamp1,
                tdsConnectionState: TdsConnectionState.TcpHandshake,
                transportLayerConnection: _transportLayerConnection1,
                firstSynTimestamp: firstSynTimestamp1,
                establishedTimestamp: tcpEstablishedTimestamp1),

            GetPacketData(preLoginTimestamp1, TdsConnectionState.PreLogin, _transportLayerConnection1),
            GetPacketData(preLoginResponseTimestamp1, TdsConnectionState.PreLoginResponse, _transportLayerConnection1),
            GetPacketData(clientHelloTimestamp1, TdsConnectionState.ClientHello, _transportLayerConnection1),
            GetPacketData(serverHelloTimestamp1, TdsConnectionState.ServerHello, _transportLayerConnection1),
            GetPacketData(keyExchangeTimestamp1, TdsConnectionState.KeyExchange, _transportLayerConnection1),
            GetPacketData(cipherChangeTimestamp1, TdsConnectionState.CipherChange, _transportLayerConnection1),
            GetPacketData(loginMessageTimestamp1, TdsConnectionState.LoginMessage, _transportLayerConnection1),
            GetPacketData(loginAckTimestamp1, TdsConnectionState.LoginAck, _transportLayerConnection1),

            GetPacketData(
                timestamp: tcpEstablishedTimestamp2,
                tdsConnectionState: TdsConnectionState.TcpHandshake,
                transportLayerConnection: _transportLayerConnection2,
                firstSynTimestamp: firstSynTimestamp2,
                establishedTimestamp: tcpEstablishedTimestamp2),

            GetPacketData(preLoginTimestamp2, TdsConnectionState.PreLogin, _transportLayerConnection2),
            GetPacketData(preLoginResponseTimestamp2, TdsConnectionState.PreLoginResponse, _transportLayerConnection2),
            GetPacketData(clientHelloTimestamp2, TdsConnectionState.ClientHello, _transportLayerConnection2),
            GetPacketData(serverHelloTimestamp2, TdsConnectionState.ServerHello, _transportLayerConnection2),
            GetPacketData(keyExchangeTimestamp2, TdsConnectionState.KeyExchange, _transportLayerConnection2),
            GetPacketData(cipherChangeTimestamp2, TdsConnectionState.CipherChange, _transportLayerConnection2),
            GetPacketData(loginMessageTimestamp2, TdsConnectionState.LoginMessage, _transportLayerConnection2),
            GetPacketData(loginAckTimestamp2, TdsConnectionState.LoginAck, _transportLayerConnection2),

            GetPacketData(
                timestamp: tcpEstablishedTimestamp3,
                tdsConnectionState: TdsConnectionState.TcpHandshake,
                transportLayerConnection: _transportLayerConnection3,
                firstSynTimestamp: firstSynTimestamp3,
                establishedTimestamp: tcpEstablishedTimestamp3),

            GetPacketData(preLoginTimestamp3, TdsConnectionState.PreLogin, _transportLayerConnection3),
            GetPacketData(preLoginResponseTimestamp3, TdsConnectionState.PreLoginResponse, _transportLayerConnection3),
            GetPacketData(clientHelloTimestamp3, TdsConnectionState.ClientHello, _transportLayerConnection3),
            GetPacketData(serverHelloTimestamp3, TdsConnectionState.ServerHello, _transportLayerConnection3),
            GetPacketData(keyExchangeTimestamp3, TdsConnectionState.KeyExchange, _transportLayerConnection3),
            GetPacketData(cipherChangeTimestamp3, TdsConnectionState.CipherChange, _transportLayerConnection3),
            GetPacketData(loginMessageTimestamp3, TdsConnectionState.LoginMessage, _transportLayerConnection3),
            GetPacketData(loginAckTimestamp3, TdsConnectionState.LoginAck, _transportLayerConnection3),
        };

        var preLoginToLoginAckLatency1 = loginAckTimestamp1 - preLoginTimestamp1;
        var preLoginToLoginAckLatency2 = loginAckTimestamp2 - preLoginTimestamp2;

        var expectedTcpHandshakeSuccessToPreLoginAverageLatency = TimeSpan.FromTicks((tcpHandshakeSuccessToPreLoginToPreLoginLatency1 + tcpHandshakeSuccessToPreLoginToPreLoginLatency2).Ticks / 2);
        var expectedPreLoginToPreLoginResponseAverageLatency = TimeSpan.FromTicks((preLoginToPreLoginResponseLatency1 + preLoginToPreLoginResponseLatency2).Ticks / 2);
        var expectedPreLoginResponseToClientHelloAverageLatency = TimeSpan.FromTicks((preLoginResponseToClientHelloLatency1 + preLoginResponseToClientHelloLatency2).Ticks / 2);
        var expectedClientHelloToServerHelloAverageLatency = TimeSpan.FromTicks((clientHelloToServerHelloLatency1 + clientHelloToServerHelloLatency2).Ticks / 2);
        var expectedServerHelloToKeyExchangeAverageLatency = TimeSpan.FromTicks((serverHelloToKeyExchangeLatency1 + serverHelloToKeyExchangeLatency2).Ticks / 2);
        var expectedKeyExchangeToCipherChangeAverageLatency = TimeSpan.FromTicks((keyExchangeToCipherChangeLatency1 + keyExchangeToCipherChangeLatency2).Ticks / 2);
        var expectedCipherChangeToLoginMessageAverageLatency = TimeSpan.FromTicks((cipherChangeToLoginMessageLatency1 + cipherChangeToLoginMessageLatency2).Ticks / 2);
        var expectedLoginMessageToLoginAckAverageLatency = TimeSpan.FromTicks((loginMessageToLoginAckLatency1 + loginMessageToLoginAckLatency2).Ticks / 2);
        var expectedPreLoginToLoginAckAverageLatency = TimeSpan.FromTicks((preLoginToLoginAckLatency1 + preLoginToLoginAckLatency2).Ticks / 2);

        // Act
        foreach (var packetData in packetDataCollection)
        {
             _sut.Process(packetData.Packet, packetData.Snapshot);
        }

        // Assert
        _sut.TcpHandshakeToPreLoginAverageLatencies.Count.Should().Be(2);
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(2);
        _sut.PreLoginResponseToClientHelloAverageLatencies.Count.Should().Be(2);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(2);
        _sut.ServerHelloToKeyExchangeAverageLatencies.Count.Should().Be(2);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(2);
        _sut.CipherChangeToLoginMessageAverageLatencies.Count.Should().Be(2);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(2);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(2);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(0);

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp1].Should().Be(expectedTcpHandshakeSuccessToPreLoginAverageLatency);
        _sut.PreLoginToPreLoginResponseAverageLatencies[preLoginResponseTimestamp1].Should().Be(expectedPreLoginToPreLoginResponseAverageLatency);
        _sut.PreLoginResponseToClientHelloAverageLatencies[clientHelloTimestamp1].Should().Be(expectedPreLoginResponseToClientHelloAverageLatency);
        _sut.ClientHelloToServerHelloAverageLatencies[serverHelloTimestamp1].Should().Be(expectedClientHelloToServerHelloAverageLatency);
        _sut.ServerHelloToKeyExchangeAverageLatencies[keyExchangeTimestamp1].Should().Be(expectedServerHelloToKeyExchangeAverageLatency);
        _sut.KeyExchangeToCipherChangeAverageLatencies[cipherChangeTimestamp1].Should().Be(expectedKeyExchangeToCipherChangeAverageLatency);
        _sut.CipherChangeToLoginMessageAverageLatencies[loginMessageTimestamp1].Should().Be(expectedCipherChangeToLoginMessageAverageLatency);
        _sut.LoginMessageToLoginAckAverageLatencies[loginAckTimestamp1].Should().Be(expectedLoginMessageToLoginAckAverageLatency);
        _sut.PreLoginToLoginAckAverageLatencies[loginAckTimestamp1].Should().Be(expectedPreLoginToLoginAckAverageLatency);

        _sut.TcpHandshakeToPreLoginAverageLatencies[preLoginTimestamp2].Should().Be(preLoginTimestamp2 - tcpEstablishedTimestamp2);
        _sut.PreLoginToPreLoginResponseAverageLatencies[preLoginResponseTimestamp3].Should().Be(preLoginResponseTimestamp3 - preLoginTimestamp3);
        _sut.PreLoginResponseToClientHelloAverageLatencies[clientHelloTimestamp2].Should().Be(clientHelloTimestamp2 - preLoginResponseTimestamp2);
        _sut.ClientHelloToServerHelloAverageLatencies[serverHelloTimestamp3].Should().Be(serverHelloTimestamp3 - clientHelloTimestamp3);
        _sut.ServerHelloToKeyExchangeAverageLatencies[keyExchangeTimestamp2].Should().Be(keyExchangeTimestamp2 - serverHelloTimestamp2);
        _sut.KeyExchangeToCipherChangeAverageLatencies[cipherChangeTimestamp3].Should().Be(cipherChangeTimestamp3 - keyExchangeTimestamp3);
        _sut.CipherChangeToLoginMessageAverageLatencies[loginMessageTimestamp2].Should().Be(loginMessageTimestamp2 - cipherChangeTimestamp2);
        _sut.LoginMessageToLoginAckAverageLatencies[loginAckTimestamp3].Should().Be(loginAckTimestamp3 - loginMessageTimestamp3);
        _sut.PreLoginToLoginAckAverageLatencies[loginAckTimestamp3].Should().Be(loginAckTimestamp3 - preLoginTimestamp3);
    }
}