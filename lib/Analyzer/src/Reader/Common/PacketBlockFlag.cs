// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Reader.Common;

/// <summary>
/// Packet block flags.
/// </summary>
internal sealed class PacketBlockFlag
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PacketBlockFlag" /> class.
    /// </summary>
    /// <param name="flag">The flag unsigned integer value.</param>
    public PacketBlockFlag(uint flag)
    {
        Flag = flag;
    }

    /// <summary>
    /// Gets the unsigned integer value of the packet flag.
    /// </summary>
    public uint Flag { get; }

    /// <summary>
    /// Gets a value indicating whether the packet is inbound.
    /// </summary>
    public bool Inbound => (Flag & (uint)PacketFlag.Inbound) == (uint)PacketFlag.Inbound;

    /// <summary>
    /// Gets a value indicating whether the packet is outbound.
    /// </summary>
    public bool Outbound => (Flag & (uint)PacketFlag.Outbound) == (uint)PacketFlag.Outbound;

    /// <summary>
    /// Gets a value indicating whether the packet was delivered using unicast.
    /// </summary>
    public bool Unicast => (Flag & (uint)PacketFlag.Unicast) == (uint)PacketFlag.Unicast;

    /// <summary>
    /// Gets a value indicating whether the packet was delivered using multicast.
    /// </summary>
    public bool Multicast => (Flag & (uint)PacketFlag.Multicast) == (uint)PacketFlag.Multicast;

    /// <summary>
    /// Gets a value indicating whether the packet was delivered using broadcast.
    /// </summary>
    public bool Broadcast => (Flag & (uint)PacketFlag.Broadcast) == (uint)PacketFlag.Broadcast;

    /// <summary>
    /// Gets a value indicating whether the packet was captured using promisuous mode.
    /// </summary>
    public bool Promiscuous => (Flag & (uint)PacketFlag.Promiscuous) == (uint)PacketFlag.Promiscuous;

    /// <summary>
    /// Gets a value indicating whether the packet FCS length is set.
    /// </summary>
    public bool FcsLength => (Flag & (uint)PacketFlag.FCSLength) == (uint)PacketFlag.FCSLength;

    /// <summary>
    /// Gets a value indicating whether the packet had a 'CRC' error.
    /// </summary>
    public bool CrcError => (Flag & (uint)PacketFlag.CrcError) == (uint)PacketFlag.CrcError;

    /// <summary>
    /// Gets a value indicating whether the packet had a 'packet too short' error.
    /// </summary>
    public bool PacketTooShortError => (Flag & (int)PacketFlag.PacketTooShortError) == (uint)PacketFlag.PacketTooShortError;

    /// <summary>
    /// Gets a value indicating whether the packet had a 'packet too short' error.
    /// </summary>
    public bool PacketTooLongError => (Flag & (uint)PacketFlag.PacketTooLongError) == (uint)PacketFlag.PacketTooLongError;

    /// <summary>
    /// Gets a value indicating whether the packet had a 'wrong inter-frame gap' error.
    /// </summary>
    public bool WrongInterFrameGapError => (Flag & (uint)PacketFlag.WrongInterFrameGapError) == (uint)PacketFlag.WrongInterFrameGapError;

    /// <summary>
    /// Gets a value indicating whether the packet had a 'unaligned frame' error.
    /// </summary>
    public bool UnalignedFrameError => (Flag & (int)PacketFlag.UnalignedFrameError) == (uint)PacketFlag.UnalignedFrameError;

    /// <summary>
    /// Gets a value indicating whether the packet had a 'start frame delimiter' error.
    /// </summary>
    public bool StartFrameDelimiterError => (Flag & (uint)PacketFlag.StartFrameDelimiterError) == (uint)PacketFlag.StartFrameDelimiterError;

    /// <summary>
    /// Gets a value indicating whether the packet had a 'preamble' error.
    /// </summary>
    public bool PreambleError => (Flag & (uint)PacketFlag.PreambleError) == (uint)PacketFlag.PreambleError;

    /// <summary>
    /// Gets a value indicating whether the packet had a 'symbol' error.
    /// </summary>
    public bool SymbolError => (Flag & (uint)PacketFlag.SymbolError) == (uint)PacketFlag.SymbolError;

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        if (obj is PacketBlockFlag packetBlockFlag)
        {
            return Flag == packetBlockFlag.Flag;
        }

        return false;
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return Flag.GetHashCode();
    }
}
