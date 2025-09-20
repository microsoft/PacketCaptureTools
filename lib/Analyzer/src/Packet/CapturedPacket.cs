// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using System;

namespace Microsoft.PacketCapture.Analyzer.Packet;

/// <summary>
/// A captured packet from .pcap/ng file.
/// </summary>
public class CapturedPacket
{
    private readonly byte[] _payload;

    /// <summary>
    /// Initializes a new instance of the <see cref="CapturedPacket" /> class.
    /// </summary>
    /// <param name="capturedDateTime">The date time the packet was captured.</param>
    /// <param name="originalPacketLength">The captured packet length.</param>
    /// <param name="payload">Packet body or payload.</param>
    /// <param name="frameNumber">Frame number.</param>
    public CapturedPacket(byte[] payload, int originalPacketLength, DateTime? capturedDateTime, int frameNumber, PhysicalFrame? physicalFrame)
    {
        CapturedDateTime = capturedDateTime;
        _payload = payload;
        OriginalPacketLength = originalPacketLength;
        FrameNumber = frameNumber;
        PhysicalFrame = physicalFrame;
        NetworkPacket = PhysicalFrame?.NetworkPacket;
        TransportSegment = NetworkPacket?.TransportSegment;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CapturedPacket" /> class.
    /// </summary>
    /// <param name="payload">Packet body or payload.</param>
    /// <param name="physicalFrame">Physical frame.</param>
    /// <param name="networkPacket">Network packet.</param>
    /// <param name="transportSegment">Transport segment.</param>
    /// <param name="capturedDateTime">Packet capture timestamp.</param>
    /// <param name="originalPacketLength">Original packet length.</param>
    /// <param name="frameNumber">Frame number.</param>
    internal CapturedPacket(
        byte[] payload,
        PhysicalFrame? physicalFrame,
        NetworkPacket? networkPacket,
        TransportSegment? transportSegment,
        DateTime? capturedDateTime,
        int originalPacketLength,
        int frameNumber)
    {
        _payload = payload;
        PhysicalFrame = physicalFrame;
        NetworkPacket = networkPacket;
        TransportSegment = transportSegment;
        CapturedDateTime = capturedDateTime;
        OriginalPacketLength = originalPacketLength;
        FrameNumber = frameNumber;
    }

    /// <summary>
    /// Gets the physical frame. Can be <c>null</c> when the physical protocol data is unrecognized or not present.
    /// </summary>
    public PhysicalFrame? PhysicalFrame { get; }

    /// <summary>
    /// Gets the network packet. Can be <c>null</c> when the network protocol data is unrecognized or not present.
    /// </summary>
    public NetworkPacket? NetworkPacket { get; }

    /// <summary>
    /// Gets the transport segment frame. Can be <c>null</c> when the transport protocol data is unrecognized or not present.
    /// </summary>
    public TransportSegment? TransportSegment { get; }

    /// <summary>
    /// Gets the date time when the packet was captured.
    /// </summary>
    public DateTime? CapturedDateTime { get; }

    /// <summary>
    /// Gets the packet body or payload.
    /// </summary>
    public ReadOnlySpan<byte> Payload => _payload;

    /// <summary>
    /// Gets the original packet length before packet capture.
    /// </summary>
    public int OriginalPacketLength { get; }

    /// <summary>
    /// Gets the captured packet length (after the packet capture operation and filters was applied).
    /// </summary>
    public int CapturedPacketLength => Payload.Length;

    /// <summary>
    /// Gets the frame number according to the packet sequence in the packet capture.
    /// </summary>
    public int FrameNumber { get; }
}