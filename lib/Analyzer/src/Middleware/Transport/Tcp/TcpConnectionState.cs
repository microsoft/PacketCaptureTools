// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;

/// <summary>
/// TCP connection state.
/// </summary>
public enum TcpConnectionState
{
    /// <summary>
    /// TCP connection is in an unknown state.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Initial SYN request has been sent.
    /// </summary>
    SynSent,

    /// <summary>
    /// Initial SYN request has been acknowledged.
    /// </summary>
    SynAcknowledged,

    /// <summary>
    /// Second SYN request has been received - simultaneous open case.
    /// </summary>
    SimultaneousOpenSecondSynReceived,

    /// <summary>
    /// First SYN request has been acknowledged - simultaneous open case.
    /// </summary>
    SimultaneousOpenFirstSynAcknowledged,

    /// <summary>
    /// TCP connection has been assumed to be established.
    /// </summary>
    AssumedEstablished,

    /// <summary>
    /// TCP connection has been established.
    /// </summary>
    Established,

    /// <summary>
    /// First FIN request has been sent.
    /// </summary>
    FirstFinishSent,

    /// <summary>
    /// First FIN request has been acknowledged.
    /// </summary>
    FirstFinishAcknowledged,

    /// <summary>
    /// Second FIN request has been sent.
    /// </summary>
    SecondFinishSent,

    /// <summary>
    /// Connection has been closed.
    /// </summary>
    Closed,
}
