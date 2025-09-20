// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet;
using System;
using System.Collections.Generic;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;

/// <summary>
/// TCP connection retransmission analysis for packets retransmitted by the packet capture source node.
/// </summary>
public class TcpConnectionRetransmissionAnalysis : TcpConnectionAnalysis
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TcpConnectionRetransmissionAnalysis" /> class.
    /// </summary>
    public TcpConnectionRetransmissionAnalysis()
        : this(default)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpConnectionRetransmissionAnalysis" /> class.
    /// </summary>
    /// <param name="retransmissionsByIpAddress">Retransmissions by IP address.</param>
    /// <param name="retransmissionsByTime">Retransmissions by time.</param>
    internal TcpConnectionRetransmissionAnalysis(
        Dictionary<IPAddress, int>? retransmissionsByIpAddress = default,
        Dictionary<DateTime, int>? retransmissionsByTime = default)
    {
        RetransmissionsByIpAddress = retransmissionsByIpAddress ?? new Dictionary<IPAddress, int>();
        RetransmissionsByTime = retransmissionsByTime ?? new Dictionary<DateTime, int>();
    }

    /// <summary>
    /// Gets TCP connection retransmissions from the source node towards the destination node. Aggregate by destination IP address.
    /// </summary>
    public Dictionary<IPAddress, int> RetransmissionsByIpAddress { get; }

    /// <summary>
    /// Gets TCP connection retransmissions from the source node towards the destination node. Aggregate by time of retransmissions.
    /// </summary>
    public Dictionary<DateTime, int> RetransmissionsByTime { get; }

    /// <inheritdoc />
    public override void Process(CapturedPacket packet, TcpConnectionSnapshot tcpConnectionSnapshot)
    {
        if (packet.NetworkPacket is null)
        {
            return;
        }

        if (!tcpConnectionSnapshot.LastPacketIsOutgoingDuplicate)
        {
            return;
        }

        var remoteIpAddress = tcpConnectionSnapshot.GetRemoteIpAddress(packet.NetworkPacket);

        if (!RetransmissionsByIpAddress.ContainsKey(remoteIpAddress))
        {
            RetransmissionsByIpAddress.Add(remoteIpAddress, 1);
        }
        else
        {
            RetransmissionsByIpAddress[remoteIpAddress]++;
        }

        if (packet.CapturedDateTime is null)
        {
            return;
        }

        var timestamp = packet.CapturedDateTime.Value.TruncateToSeconds();

        if (!RetransmissionsByTime.ContainsKey(timestamp))
        {
            RetransmissionsByTime.Add(timestamp, 1);
        }
        else
        {
            RetransmissionsByTime[timestamp]++;
        }
    }
}
