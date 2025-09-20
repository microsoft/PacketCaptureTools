// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using System;
using System.Collections.Generic;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;

/// <summary>
/// TCP connection analytics and status information.
/// </summary>
public class TcpConnectionSnapshot : TransportConnectionSnapshot
{
    private static readonly HashSet<TcpConnectionState> TcpHandshakeOrEstablishedConnectionStates =
    [
        TcpConnectionState.Established,
        TcpConnectionState.AssumedEstablished,
        TcpConnectionState.SynSent,
        TcpConnectionState.SynAcknowledged,
        TcpConnectionState.SimultaneousOpenFirstSynAcknowledged,
        TcpConnectionState.SimultaneousOpenSecondSynReceived,
    ];

    private DateTime? _lastOutgoingPacketTimestamp;
    private bool _incomingSequenceNumberHadPayload;
    private bool _outgoingSequenceNumberHadZeroPayload;
    private bool _outgoingSequenceNumberHadNonZeroPayload;

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpConnectionSnapshot" /> class.
    /// </summary>
    /// <param name="ipPacket">IP packet.</param>
    /// <param name="tcpSegment">TCP segment.</param>
    /// <param name="transportConnection">Connection information.</param>
    /// <param name="packetFlowDetector">Packet flow detector.</param>
    /// <param name="packetCaptureTimestamp">Packet capture timestamp.</param>
    internal TcpConnectionSnapshot(
        IpPacket ipPacket,
        TcpSegment tcpSegment,
        TransportLayerConnection transportConnection,
        IPacketFlowDetector packetFlowDetector,
        DateTime? packetCaptureTimestamp = null)
        : base(transportConnection, packetFlowDetector)
    {
        _ = ipPacket ?? throw new ArgumentNullException(nameof(ipPacket));
        _ = tcpSegment ?? throw new ArgumentNullException(nameof(tcpSegment));

        TcpState = new UnknownTcpState();
        LastPacketTcpFlags = new TcpFlags();
        UpdateTcpConnectionSnapshot(tcpSegment, ipPacket, packetCaptureTimestamp);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpConnectionSnapshot" /> class.
    /// </summary>
    /// <param name="transportConnection">Transport layer connection.</param>
    /// <param name="packetFlowDetector">Packet flow detector, with respect to the node on which the capture was performed.</param>
    /// <param name="lastOutgoingPacketTimestamp">Timestamp of the last outgoing packet.</param>
    /// <param name="incomingSequenceNumberHadPayload">Did a packet with the incoming sequence number have a payload.</param>
    /// <param name="outgoingSequenceNumberHadZeroPayload">Did a packet with the outgoing sequence number have a zero payload.</param>
    /// <param name="outgoingSequenceNumberHadNonZeroPayload">Did a packet with the outgoing sequence number have a non-zero payload.</param>
    /// <param name="lastPacketTcpFlags">Last packet's TCP flags.</param>
    /// <param name="tcpState">TCP state.</param>
    /// <param name="lastPacketDirection">Last packet direction.</param>
    /// <param name="incomingLastSeenSequenceNumber">Last seen incoming sequence number.</param>
    /// <param name="incomingLastSeenAcknowledgementNumber">Last seen incoming acknowledgement number.</param>
    /// <param name="incomingNextExpectedSequenceNumber">Next expected incoming sequence number.</param>
    /// <param name="outgoingLastSeenSequenceNumber">Last seen outgoing sequence number.</param>
    /// <param name="outgoingLastSeenAcknowledgementNumber">Last seen outgoing acknowledgement number.</param>
    /// <param name="outOfOrderPackets">Number of packets received out of order.</param>
    /// <param name="incomingDuplicatePackets">Number of incoming duplicate packets.</param>
    /// <param name="outgoingDuplicatePackets">Number of outgoing duplicate packets.</param>
    /// <param name="outgoingDuplicateAcknowledgements">Number of duplicate acknowledgements.</param>
    /// <param name="lastPacketIsOutOfOrder">Was the last packet out of order.</param>
    /// <param name="lastPacketIsIncomingDuplicate">Was the last packet incoming duplicate.</param>
    /// <param name="lastPacketIsOutgoingDuplicate">Was the last packet outgoing duplicate.</param>
    /// <param name="lastPacketIsOutgoingDuplicateAcknowledgement">Was the last packet outgoing duplicate acknowledgement.</param>
    /// <param name="lastRoundTripTime">Last round trip time.</param>
    /// <param name="firstSynTimestamp">First SYN flag timestamp.</param>
    /// <param name="establishedTimestamp">Connection established timestamp.</param>
    internal TcpConnectionSnapshot(
        TransportLayerConnection transportConnection,
        IPacketFlowDetector packetFlowDetector,
        DateTime? lastOutgoingPacketTimestamp,
        bool incomingSequenceNumberHadPayload,
        bool outgoingSequenceNumberHadZeroPayload,
        bool outgoingSequenceNumberHadNonZeroPayload,
        TcpFlags? lastPacketTcpFlags,
        TcpState? tcpState,
        PacketDirection lastPacketDirection,
        uint? incomingLastSeenSequenceNumber,
        uint? incomingLastSeenAcknowledgementNumber,
        uint? incomingNextExpectedSequenceNumber,
        uint? outgoingLastSeenSequenceNumber,
        uint? outgoingLastSeenAcknowledgementNumber,
        int outOfOrderPackets,
        int incomingDuplicatePackets,
        int outgoingDuplicatePackets,
        int outgoingDuplicateAcknowledgements,
        bool lastPacketIsOutOfOrder,
        bool lastPacketIsIncomingDuplicate,
        bool lastPacketIsOutgoingDuplicate,
        bool lastPacketIsOutgoingDuplicateAcknowledgement,
        TimeSpan? lastRoundTripTime,
        DateTime? firstSynTimestamp,
        DateTime? establishedTimestamp)
        : base(transportConnection, packetFlowDetector)
    {
        _lastOutgoingPacketTimestamp = lastOutgoingPacketTimestamp;
        _incomingSequenceNumberHadPayload = incomingSequenceNumberHadPayload;
        _outgoingSequenceNumberHadZeroPayload = outgoingSequenceNumberHadZeroPayload;
        _outgoingSequenceNumberHadNonZeroPayload = outgoingSequenceNumberHadNonZeroPayload;
        TcpState = tcpState ?? new UnknownTcpState();
        LastPacketTcpFlags = lastPacketTcpFlags ?? new TcpFlags();
        LastPacketDirection = lastPacketDirection;
        IncomingLastSeenSequenceNumber = incomingLastSeenSequenceNumber;
        IncomingLastSeenAcknowledgementNumber = incomingLastSeenAcknowledgementNumber;
        IncomingNextExpectedSequenceNumber = incomingNextExpectedSequenceNumber;
        OutgoingLastSeenSequenceNumber = outgoingLastSeenSequenceNumber;
        OutgoingLastSeenAcknowledgementNumber = outgoingLastSeenAcknowledgementNumber;
        OutOfOrderPackets = outOfOrderPackets;
        IncomingDuplicatePackets = incomingDuplicatePackets;
        OutgoingDuplicatePackets = outgoingDuplicatePackets;
        OutgoingDuplicateAcknowledgements = outgoingDuplicateAcknowledgements;
        LastPacketIsOutOfOrder = lastPacketIsOutOfOrder;
        LastPacketIsIncomingDuplicate = lastPacketIsIncomingDuplicate;
        LastPacketIsOutgoingDuplicate = lastPacketIsOutgoingDuplicate;
        LastPacketIsOutgoingDuplicateAcknowledgement = lastPacketIsOutgoingDuplicateAcknowledgement;
        LastRoundTripTime = lastRoundTripTime;
        FirstSynTimestamp = firstSynTimestamp;
        EstablishedTimestamp = establishedTimestamp;
        TotalConnectionPackets++;
    }

    /// <summary>
    /// Gets the TCP connection state.
    /// </summary>
    public TcpConnectionState TcpConnectionState => TcpState.TcpConnectionState;

    /// <summary>
    /// Gets the sequence number of the last processed incoming TCP segment.
    /// </summary>
    public uint? IncomingLastSeenSequenceNumber { get; private set; }

    /// <summary>
    /// Gets the acknowledgement number of the last processed incoming TCP segment.
    /// </summary>
    public uint? IncomingLastSeenAcknowledgementNumber { get; private set; }

    /// <summary>
    /// Gets the expected sequence number of next incoming TCP segment.
    /// </summary>
    public uint? IncomingNextExpectedSequenceNumber { get; private set; }

    /// <summary>
    /// Gets the sequence number of the last processed outgoing TCP segment.
    /// </summary>
    public uint? OutgoingLastSeenSequenceNumber { get; private set; }

    /// <summary>
    /// Gets the acknowledgement number of the last processed outgoing TCP segment.
    /// </summary>
    public uint? OutgoingLastSeenAcknowledgementNumber { get; private set; }

    /// <summary>
    /// Gets the total number of packets that were captured for this connection.
    /// </summary>
    public int TotalConnectionPackets { get; private set; }

    /// <summary>
    /// Gets the number of packets received out-of-order.
    /// </summary>
    public int OutOfOrderPackets { get; private set; }

    /// <summary>
    /// Gets the number of incoming duplicate packets.
    /// </summary>
    public int IncomingDuplicatePackets { get; private set; }

    /// <summary>
    /// Gets the number of outgoing duplicate packets.
    /// </summary>
    public int OutgoingDuplicatePackets { get; private set; }

    /// <summary>
    /// Gets the number of outgoing duplicate acknowledgements.
    /// </summary>
    public int OutgoingDuplicateAcknowledgements { get; private set; }

    /// <summary>
    /// Gets a value indicating whether the last packet is out of order packet.
    /// </summary>
    public bool LastPacketIsOutOfOrder { get; private set; }

    /// <summary>
    /// Gets a value indicating whether the last packet is incoming duplicate packet.
    /// </summary>
    public bool LastPacketIsIncomingDuplicate { get; private set; }

    /// <summary>
    /// Gets a value indicating whether the last packet is outgoing duplicate packet.
    /// </summary>
    public bool LastPacketIsOutgoingDuplicate { get; private set; }

    /// <summary>
    /// Gets a value indicating whether the last packet is outgoing duplicate acknowledgement packet.
    /// </summary>
    public bool LastPacketIsOutgoingDuplicateAcknowledgement { get; private set; }

    /// <summary>
    /// Gets the last round trip time.
    /// </summary>
    public TimeSpan? LastRoundTripTime { get; private set; }

    /// <summary>
    /// Gets the last packet direction.
    /// </summary>
    public PacketDirection LastPacketDirection { get; private set; }

    /// <summary>
    /// Gets a value indicating whether the tcp connection is currently performing tcp handshake or is in established state.
    /// </summary>
    public bool IsConnectionInTcpHandshakeOrEstablishedConnectionState => TcpHandshakeOrEstablishedConnectionStates.Contains(TcpState.TcpConnectionState);

    /// <summary>
    /// Gets the last packet Tcp flags.
    /// </summary>
    internal TcpFlags LastPacketTcpFlags { get; private set; }

    /// <summary>
    /// Gets the state of the TCP connection snapshot.
    /// </summary>
    internal TcpState TcpState { get; private set; }

    /// <summary>
    /// Gets the timestamp of the packet with the first SYN flag.
    /// </summary>
    internal DateTime? FirstSynTimestamp { get; private set; }

    /// <summary>
    /// Gets the timestamp of the packet which established the connection.
    /// </summary>
    internal DateTime? EstablishedTimestamp { get; private set; }

    /// <summary>
    /// Gets the latency of TCP handshake.
    /// </summary>
    internal TimeSpan? TcpHandshakeLatency => EstablishedTimestamp - FirstSynTimestamp;

    /// <summary>
    /// Update <see cref="TcpConnectionSnapshot" /> analytics based on <see cref="TcpSegment" />.
    /// </summary>
    /// <param name="tcpSegment">TCP segment used to update the state.</param>
    /// <param name="ipPacket">IP packet used to update the state.</param>
    /// <param name="packetCaptureTimestamp">Packet capture timestamp.</param>
    internal virtual void UpdateTcpConnectionSnapshot(TcpSegment tcpSegment, IpPacket ipPacket, DateTime? packetCaptureTimestamp = null)
    {
        TotalConnectionPackets++;

        ResetLastPacketFlags();
        LastPacketDirection = GetPacketDirection(ipPacket);

        if (LastPacketDirection == PacketDirection.Incoming)
        {
            if (IsDuplicateIncoming(tcpSegment))
            {
                IncomingDuplicatePackets++;
                LastPacketIsIncomingDuplicate = true;

                return;
            }

            if (IsOutOfOrder(tcpSegment))
            {
                OutOfOrderPackets++;
                LastPacketIsOutOfOrder = true;

                return;
            }
        }
        else if (LastPacketDirection == PacketDirection.Outgoing)
        {
            if (IsDuplicateOutgoing(tcpSegment, out var isDuplicateAck))
            {
                if (isDuplicateAck)
                {
                    OutgoingDuplicateAcknowledgements++;
                    LastPacketIsOutgoingDuplicateAcknowledgement = true;
                }
                else
                {
                    OutgoingDuplicatePackets++;
                    LastPacketIsOutgoingDuplicate = true;
                }
            }
        }

        UpdateTcpState(tcpSegment);
        UpdateStateBasedTimestamps(packetCaptureTimestamp);
        UpdateRoundTripTime(packetCaptureTimestamp, tcpSegment, LastPacketDirection);
        UpdateLastSeenNumbers(tcpSegment, LastPacketDirection);
    }

    /// <summary>
    /// Returns the remote IP address based on the flow direction of the packet.
    /// </summary>
    /// <param name="packet">Network packet.</param>
    /// <returns>For outgoing packets, the remote address is the destination, and for incoming it is the source.</returns>
    internal IPAddress GetRemoteIpAddress(NetworkPacket packet)
    {
        var packetDirection = GetPacketDirection(packet);
        var remoteIpAddress = packetDirection == PacketDirection.Outgoing ? packet.DestinationAddress
                                                                          : packet.SourceAddress;
        return remoteIpAddress;
    }

    private PacketDirection GetPacketDirection(NetworkPacket packet)
    {
        return PacketFlowDetector.GetNetworkPacketDirection(packet);
    }

    private void ResetLastPacketFlags()
    {
        LastPacketIsOutOfOrder = false;
        LastPacketIsIncomingDuplicate = false;
        LastPacketIsOutgoingDuplicate = false;
        LastPacketIsOutgoingDuplicateAcknowledgement = false;
    }

    private bool IsDuplicateIncoming(TcpSegment tcpSegment)
    {
        // if the sequence number or the received packet is a duplicate, the packet is duplicate unless it has has empty payload and only ACK flag set
        if (tcpSegment.SequenceNumber != IncomingLastSeenSequenceNumber)
        {
            return false;
        }

        if (tcpSegment.NonTruncatedPayloadLength == 0)
        {
            return false;
        }

        // packet is not a duplicate if all previous packets with the same incoming sequence number had no payload
        return _incomingSequenceNumberHadPayload;
    }

    private bool IsDuplicateOutgoing(TcpSegment tcpSegment, out bool isDuplicateAck)
    {
        isDuplicateAck = false;

        if (tcpSegment.SequenceNumber != OutgoingLastSeenSequenceNumber ||
            tcpSegment.AckNumber != OutgoingLastSeenAcknowledgementNumber)
        {
            return false;
        }

        if (tcpSegment.NonTruncatedPayloadLength == 0)
        {
            if (_outgoingSequenceNumberHadZeroPayload)
            {
                isDuplicateAck = true;
                return true;
            }
        }
        else
        {
            if (_outgoingSequenceNumberHadNonZeroPayload)
            {
                return true;
            }
        }

        return false;
    }

    private bool IsOutOfOrder(TcpSegment tcpSegment)
    {
        if (IncomingNextExpectedSequenceNumber is null)
        {
            return false;
        }

        return tcpSegment.SequenceNumber < IncomingNextExpectedSequenceNumber;
    }

    private void UpdateTcpState(TcpSegment tcpSegment)
    {
        TcpState = TcpState.GetNextState(tcpSegment.Flags);
        LastPacketTcpFlags = tcpSegment.Flags;
    }

    private void UpdateStateBasedTimestamps(DateTime? packetCaptureTimestamp = null)
    {
        if (TcpState.TcpConnectionState == TcpConnectionState.SynSent)
        {
            FirstSynTimestamp = packetCaptureTimestamp;
            EstablishedTimestamp = null;
        }
        else if (TcpState.TcpConnectionState == TcpConnectionState.Established)
        {
            EstablishedTimestamp = packetCaptureTimestamp;
        }
    }

    private void UpdateLastSeenNumbers(TcpSegment tcpSegment, PacketDirection packetDirection)
    {
        if (packetDirection == PacketDirection.Incoming)
        {
            if ((IncomingLastSeenSequenceNumber != tcpSegment.SequenceNumber ||
                 IncomingLastSeenAcknowledgementNumber != tcpSegment.AckNumber) &&
                _incomingSequenceNumberHadPayload)
            {
                _incomingSequenceNumberHadPayload = false;
            }

            if (!_incomingSequenceNumberHadPayload &&
                tcpSegment.NonTruncatedPayloadLength != 0)
            {
                _incomingSequenceNumberHadPayload = true;
            }

            IncomingLastSeenSequenceNumber = tcpSegment.SequenceNumber;
            IncomingLastSeenAcknowledgementNumber = tcpSegment.AckNumber;
            IncomingNextExpectedSequenceNumber = (uint?)(tcpSegment.SequenceNumber + tcpSegment.NonTruncatedPayloadLength);
        }
        else if (packetDirection == PacketDirection.Outgoing)
        {
            if (OutgoingLastSeenSequenceNumber != tcpSegment.SequenceNumber ||
                OutgoingLastSeenAcknowledgementNumber != tcpSegment.AckNumber)
            {
                if (_outgoingSequenceNumberHadNonZeroPayload)
                {
                    _outgoingSequenceNumberHadNonZeroPayload = false;
                }

                if (_outgoingSequenceNumberHadZeroPayload)
                {
                    _outgoingSequenceNumberHadZeroPayload = false;
                }
            }

            if (!_outgoingSequenceNumberHadNonZeroPayload &&
                tcpSegment.NonTruncatedPayloadLength != 0)
            {
                _outgoingSequenceNumberHadNonZeroPayload = true;
            }

            if (!_outgoingSequenceNumberHadZeroPayload &&
                tcpSegment.NonTruncatedPayloadLength == 0)
            {
                _outgoingSequenceNumberHadZeroPayload = true;
            }

            OutgoingLastSeenSequenceNumber = tcpSegment.SequenceNumber;
            OutgoingLastSeenAcknowledgementNumber = tcpSegment.AckNumber;
        }
    }

    private void UpdateRoundTripTime(DateTime? packetCaptureTimestamp, TcpSegment tcpSegment, PacketDirection packetDirection)
    {
        if (packetDirection == PacketDirection.Outgoing)
        {
            if (_lastOutgoingPacketTimestamp is not null)
            {
                return;
            }

            _lastOutgoingPacketTimestamp = packetCaptureTimestamp;
            LastRoundTripTime = null;
        }
        else
        {
            if (packetCaptureTimestamp == null ||
                _lastOutgoingPacketTimestamp == null ||
                tcpSegment.AckNumber <= IncomingLastSeenAcknowledgementNumber)
            {
                return;
            }

            LastRoundTripTime = packetCaptureTimestamp.Value.Subtract(_lastOutgoingPacketTimestamp.Value);
            _lastOutgoingPacketTimestamp = null;
        }
    }
}