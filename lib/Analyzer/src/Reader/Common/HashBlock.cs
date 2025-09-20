// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;
using System.Text;

namespace Microsoft.PacketCapture.Analyzer.Reader.Common;

/// <summary>
/// Network packet hash information.
/// </summary>
internal sealed class HashBlock
{
    /// <summary>
    /// Initializes a new instance of the <see cref="HashBlock" /> class.
    /// </summary>
    /// <param name="hashBytes">The byte sequence containing hash block information.</param>
    /// <exception cref="ArgumentNullException"><paramref name="hashBytes" /> cannot be null.</exception>
    /// <exception cref="ArgumentException"><paramref name="hashBytes" /> cannot have a length of less than 2.</exception>
    public HashBlock(byte[] hashBytes)
    {
        _ = hashBytes ?? throw new ArgumentNullException(nameof(hashBytes));

        if (hashBytes.Length < 2)
        {
            throw new ArgumentException($"'{nameof(hashBytes)}' cannot have a length of less than 2, actual length '{hashBytes.Length}'.");
        }

        var tempAlgorithm = hashBytes[0];
        Algorithm = Enum.IsDefined(typeof(HashAlgorithm), tempAlgorithm) ? (HashAlgorithm)tempAlgorithm : HashAlgorithm.Invalid;

        Value = hashBytes.Skip(1).Take(hashBytes.Length - 1).ToArray();
        StringValue = Encoding.UTF8.GetString(Value);
    }

    /// <summary>
    /// Gets the hashblock's hash algorithm.
    /// </summary>
    public HashAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the hash value of the packet.
    /// </summary>
    public byte[] Value { get; }

    /// <summary>
    /// Gets the string value of the packet hash.
    /// </summary>
    public string StringValue { get; }
}
