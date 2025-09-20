// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport;

/// <summary>
/// Transport layer connection defined by source and destination IP addresses and ports.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TransportLayerConnection" /> class.
/// </remarks>
/// <param name="sourceIpAddress">Source IP address.</param>
/// <param name="destinationIpAddress">Destination IP address.</param>
/// <param name="sourcePort">Source port.</param>
/// <param name="destinationPort">Destination port.</param>
/// <exception cref="ArgumentNullException">Throws when sourceIpAddress or destinationIpAddress is null.</exception>
public class TransportLayerConnection(IPAddress sourceIpAddress, IPAddress destinationIpAddress, int sourcePort, int destinationPort) : IEquatable<TransportLayerConnection>
{

    /// <summary>
    /// Gets source IP address.
    /// </summary>
    public IPAddress SourceIpAddress { get; } = sourceIpAddress ?? throw new ArgumentNullException(nameof(sourceIpAddress));

    /// <summary>
    /// Gets destination IP address.
    /// </summary>
    public IPAddress DestinationIpAddress { get; } = destinationIpAddress ?? throw new ArgumentNullException(nameof(destinationIpAddress));

    /// <summary>
    /// Gets source port.
    /// </summary>
    public int SourcePort { get; } = sourcePort;

    /// <summary>
    /// Gets destination port.
    /// </summary>
    public int DestinationPort { get; } = destinationPort;

    /// <inheritdoc />
    public bool Equals(TransportLayerConnection? connection) => IsSameConnection(connection, out _);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is TransportLayerConnection connection && Equals(connection);

    /// <inheritdoc />
    public override int GetHashCode() =>
        SourceIpAddress.GetHashCode() <= DestinationIpAddress.GetHashCode()
            ? (SourceIpAddress, DestinationIpAddress, SourcePort, DestinationPort).GetHashCode()
            : (DestinationIpAddress, SourceIpAddress, DestinationPort, SourcePort).GetHashCode();

    /// <summary>
    /// Determines whether the specified <see cref="TransportLayerConnection" /> is equal to the current <see cref="TransportLayerConnection" />.
    /// </summary>
    /// <param name="other">The <see cref="TransportLayerConnection" /> to compare with the current object.</param>
    /// <param name="hasSameDirection">Determines whether the specified <see cref="TransportLayerConnection" /> is has the same direction as the current <see cref="TransportLayerConnection" />.</param>
    /// <returns>true if the specified <see cref="TransportLayerConnection" /> is equal to the current object; otherwise, false.</returns>
    public bool IsSameConnection(TransportLayerConnection? other, out bool hasSameDirection)
    {
        hasSameDirection = false;

        if (other is null)
        {
            return false;
        }

        var sourceAndDestinationAreEqual = Equals(other.SourceIpAddress, SourceIpAddress) &&
                                           Equals(other.DestinationIpAddress, DestinationIpAddress) &&
                                           other.SourcePort == SourcePort &&
                                           other.DestinationPort == DestinationPort;

        if (sourceAndDestinationAreEqual)
        {
            hasSameDirection = true;
            return true;
        }

        var sourceAndDestinationAreSwapped = Equals(other.SourceIpAddress, DestinationIpAddress) &&
                                             Equals(other.DestinationIpAddress, SourceIpAddress) &&
                                             other.SourcePort == DestinationPort &&
                                             other.DestinationPort == SourcePort;

        return sourceAndDestinationAreSwapped;
    }

    /// <summary>
    /// Determines whether the specified <see cref="NetworkLayerConnection" /> has the same source and destination IPs as the current <see cref="TransportLayerConnection" />.
    /// </summary>
    /// <param name="other">The <see cref="NetworkLayerConnection" /> to compare with the current object.</param>
    /// <param name="hasSameDirection">Determines whether the specified <see cref="NetworkLayerConnection" /> is has the same direction as the current <see cref="TransportLayerConnection" />.</param>
    /// <returns>true if the specified <see cref="NetworkLayerConnection" /> has the same source and destination IPs as the current object; otherwise, false.</returns>
    public bool IsSameConnection(NetworkLayerConnection other, out bool hasSameDirection)
    {
        hasSameDirection = false;

        if (other == null)
        {
            return false;
        }

        var sourceAndDestinationAreEqual = Equals(other.SourceIpAddress, SourceIpAddress) &&
                                           Equals(other.DestinationIpAddress, DestinationIpAddress);

        if (sourceAndDestinationAreEqual)
        {
            hasSameDirection = true;
            return true;
        }

        var sourceAndDestinationAreSwapped = Equals(other.SourceIpAddress, DestinationIpAddress) &&
                                             Equals(other.DestinationIpAddress, SourceIpAddress);

        return sourceAndDestinationAreSwapped;
    }

    /// <summary>
    /// Gets the other IpAddress of the connection.
    /// </summary>
    /// <param name="ipAddress">Source or destination IP address.</param>
    /// <returns>Source IP address if destination IP address is passed as a parameter, destination IP address of source IP address is passed as a parameter, null if neither is passed.</returns>
    public IPAddress? GetOtherIpAddress(IPAddress ipAddress)
    {
        if (ipAddress.Equals(SourceIpAddress))
        {
            return DestinationIpAddress;
        }

        if (ipAddress.Equals(DestinationIpAddress))
        {
            return SourceIpAddress;
        }

        return default;
    }
}
