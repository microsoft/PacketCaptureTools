// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using System;
using System.Collections.Generic;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Test.Common;

internal class SnapshotFixtureFactory
{
    internal TcpConnectionSnapshot CreateTcpConnectionSnapshotFixture(
        TransportLayerConnection transportConnection,
        IPacketFlowDetector? packetFlowDetector = null,
        DateTime? lastOutgoingPacketTimestamp = null,
        bool incomingSequenceNumberHadPayload = false,
        bool outgoingSequenceNumberHadZeroPayload = false,
        bool outgoingSequenceNumberHadNonZeroPayload = false,
        TcpConnectionState tcpConnectionState = TcpConnectionState.Unknown,
        PacketDirection lastPacketDirection = PacketDirection.Unknown,
        TcpFlags? lastPacketTcpFlags = null,
        uint? incomingLastSeenSequenceNumber = null,
        uint? incomingLastSeenAcknowledgementNumber = null,
        uint? incomingNextExpectedSequenceNumber = null,
        uint? outgoingLastSeenSequenceNumber = null,
        uint? outgoingLastSeenAcknowledgementNumber = null,
        int outOfOrderPackets = 0,
        int incomingDuplicatePackets = 0,
        int outgoingDuplicatePackets = 0,
        int outgoingDuplicateAcknowledgements = 0,
        bool lastPacketIsOutOfOrder = false,
        bool lastPacketIsIncomingDuplicate = false,
        bool lastPacketIsOutgoingDuplicate = false,
        bool lastPacketIsOutgoingDuplicateAcknowledgement = false,
        TimeSpan? lastRoundTripTime = null,
        DateTime? firstSynTimestamp = null,
        DateTime? establishedTimestamp = null)
    {
        return new TcpConnectionSnapshot(
            transportConnection: transportConnection,
            packetFlowDetector: packetFlowDetector ?? new ReferenceIpPacketFlowDetector(new HashSet<IPAddress> { IPAddress.Any }),
            lastOutgoingPacketTimestamp: lastOutgoingPacketTimestamp,
            incomingSequenceNumberHadPayload: incomingSequenceNumberHadPayload,
            outgoingSequenceNumberHadZeroPayload: outgoingSequenceNumberHadZeroPayload,
            outgoingSequenceNumberHadNonZeroPayload: outgoingSequenceNumberHadNonZeroPayload,
            tcpState: CreateTcpState(tcpConnectionState),
            lastPacketTcpFlags: lastPacketTcpFlags,
            lastPacketDirection: lastPacketDirection,
            incomingLastSeenSequenceNumber: incomingLastSeenSequenceNumber,
            incomingLastSeenAcknowledgementNumber: incomingLastSeenAcknowledgementNumber,
            incomingNextExpectedSequenceNumber: incomingNextExpectedSequenceNumber,
            outgoingLastSeenSequenceNumber: outgoingLastSeenSequenceNumber,
            outgoingLastSeenAcknowledgementNumber: outgoingLastSeenAcknowledgementNumber,
            outOfOrderPackets: outOfOrderPackets,
            incomingDuplicatePackets: incomingDuplicatePackets,
            outgoingDuplicatePackets: outgoingDuplicatePackets,
            outgoingDuplicateAcknowledgements: outgoingDuplicateAcknowledgements,
            lastPacketIsOutOfOrder: lastPacketIsOutOfOrder,
            lastPacketIsIncomingDuplicate: lastPacketIsIncomingDuplicate,
            lastPacketIsOutgoingDuplicate: lastPacketIsOutgoingDuplicate,
            lastPacketIsOutgoingDuplicateAcknowledgement: lastPacketIsOutgoingDuplicateAcknowledgement,
            lastRoundTripTime: lastRoundTripTime,
            firstSynTimestamp: firstSynTimestamp,
            establishedTimestamp: establishedTimestamp);
    }

    internal TdsConnectionSnapshot CreateTdsConnectionSnapshotFixture(
        TcpSegment tcpSegment,
        TcpConnectionSnapshot tcpConnectionSnapshot,
        TdsConnectionState tdsConnectionState = TdsConnectionState.Unknown)
    {
        return new TdsConnectionSnapshot(
            segment: tcpSegment,
            tcpConnectionSnapshot: tcpConnectionSnapshot,
            state: CreateTdsState(tdsConnectionState, tcpConnectionSnapshot.PacketFlowDetector));
    }

    internal TcpState CreateTcpState(TcpConnectionState tcpConnectionState)
    {
        switch (tcpConnectionState)
        {
            case TcpConnectionState.AssumedEstablished:
                return new AssumedEstablishedTcpState();

            case TcpConnectionState.Established:
                return new EstablishedTcpState();

            case TcpConnectionState.Closed:
                return new ClosedTcpState();

            case TcpConnectionState.FirstFinishAcknowledged:
                return new FirstFinishAcknowledgedTcpState();

            case TcpConnectionState.FirstFinishSent:
                return new FirstFinishSentTcpState();

            case TcpConnectionState.SecondFinishSent:
                return new SecondFinishSentTcpState();

            case TcpConnectionState.SimultaneousOpenFirstSynAcknowledged:
                return new SimultaneousOpenFirstSynAcknowledgedTcpState();

            case TcpConnectionState.SimultaneousOpenSecondSynReceived:
                return new SimultaneousOpenSecondSynReceivedTcpState();

            case TcpConnectionState.SynAcknowledged:
                return new SynAcknowledgedTcpState();

            case TcpConnectionState.SynSent:
                return new SynSentTcpState();

            case TcpConnectionState.Unknown:
            default:
                return new UnknownTcpState();
        }
    }

    internal TdsState CreateTdsState(TdsConnectionState tdsConnectionState, IPacketFlowDetector packetFlowDetector)
    {
        switch (tdsConnectionState)
        {
            case TdsConnectionState.TcpHandshake:
                return new TcpHandshakeTdsState(packetFlowDetector);

            case TdsConnectionState.PreLogin:
                return new PreLoginTdsState(packetFlowDetector);

            case TdsConnectionState.PreLoginResponse:
                return new PreLoginResponseTdsState(packetFlowDetector);

            case TdsConnectionState.ClientHello:
                return new ClientHelloTdsState(packetFlowDetector);

            case TdsConnectionState.ServerHello:
                return new ServerHelloTdsState(packetFlowDetector);

            case TdsConnectionState.KeyExchange:
                return new KeyExchangeTdsState(packetFlowDetector);

            case TdsConnectionState.CipherChange:
                return new CipherChangeTdsState(packetFlowDetector);

            case TdsConnectionState.LoginMessage:
                return new LoginMessageTdsState(packetFlowDetector);

            case TdsConnectionState.LoginAck:
                return new LoginAckTdsState(packetFlowDetector);

            case TdsConnectionState.ClosedWithError:
                return new ConnectionClosedWithErrorTdsState(packetFlowDetector);

            case TdsConnectionState.Unknown:
            default:
                return new UnknownTdsState(packetFlowDetector);
        }
    }
}