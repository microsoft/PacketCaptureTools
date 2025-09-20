// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Extensions.Size;

/// <summary>
/// Size enum manager.
/// </summary>
internal class SizeEnumManager
{
    private readonly List<string> _fileSizeEnumStringList;
    private readonly Dictionary<SizeEnum, int> _fileSizeEnumReverseLookup;

    /// <summary>
    /// Initializes a new instance of the <see cref="SizeEnumManager" /> class.
    /// </summary>
    public SizeEnumManager()
    {
        _fileSizeEnumStringList = new List<string>();
        _fileSizeEnumReverseLookup = new Dictionary<SizeEnum, int>();

        foreach (var enumValue in Enum.GetValues(typeof(SizeEnum)).Cast<SizeEnum>())
        {
            if (enumValue == default)
            {
                continue;
            }

            var localIndex = _fileSizeEnumStringList.Count;
            _fileSizeEnumStringList.Insert(localIndex, enumValue.ToString());
            _fileSizeEnumReverseLookup.Add(enumValue, localIndex);
        }
    }

    /// <summary>
    /// Gets enum string from index.
    /// </summary>
    /// <param name="key">index to search for.</param>
    public string this[int key] => _fileSizeEnumStringList[key];

    /// <summary>
    /// Gets index for given enum.
    /// </summary>
    /// <param name="key">enum to get index for.</param>
    public int this[SizeEnum key] => _fileSizeEnumReverseLookup[key];
}