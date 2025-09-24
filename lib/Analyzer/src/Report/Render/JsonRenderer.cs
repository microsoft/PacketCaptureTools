using Microsoft.PacketCapture.Analyzer.Report.Graph;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Microsoft.PacketCapture.Analyzer.Report.Render;

public class JsonRenderer : IRenderer
{
    private readonly JsonObject _root;
    private JsonObject _currentObject;

    public JsonRenderer()
    {
        _root = new JsonObject
        {
            ["sections"] = new JsonArray()
        };
        _currentObject = _root;
    }

    public void AddGraph(GraphData graphData, Func<long, string> xValueFormatter, Func<long, string> yValueFormatter)
    {
        _currentObject.Add("graph", new JsonObject
        {
            ["xAxisLabel"] = graphData.XAxisLabel,
            ["yAxisLabel"] = graphData.YAxisLabel,
            ["xAxisData"] = new JsonArray([.. graphData.XAxisData.Select(v => (JsonNode)xValueFormatter(v))]),
            ["yAxisData"] = new JsonArray([.. graphData.YAxisData.Select(v => (JsonNode)yValueFormatter(v))])
        });
    }

    public void AddHeader(string? title, string? description)
    {
        if (!string.IsNullOrEmpty(title))
        {
            _currentObject["title"] = title;
        }

        if (!string.IsNullOrEmpty(description))
        {
            _currentObject["description"] = description;
        }
    }

    public void AddKeyValue(string key, string value)
    {
        _currentObject[key] = value;
    }

    public void AddMessage(string message)
    {
        _currentObject.TryAdd("messages", new JsonArray());
        _currentObject["messages"]?.AsArray().Add(message);
    }

    public void StartSection()
    {
        var newSection = new JsonObject();
        _currentObject.TryAdd("sections", new JsonArray());
        _currentObject["sections"]?.AsArray().Add(newSection);
        _currentObject = newSection;
    }

    public void AddSectionTitle(string title)
    {
        _currentObject["title"] = title;
    }

    public void EndSection()
    {
        if (_currentObject == _root)
        {
            return;
        }

        JsonObject? parent;

        if (_currentObject.Parent is JsonArray)
        {
            parent = _currentObject.Parent?.Parent?.AsObject();
        }
        else
        {
            parent = _currentObject.Parent?.AsObject();
        }

        if (parent is null)
        {
            return;
        }

        _currentObject = parent;
    }

    public void AddTable(IReadOnlyList<string> headers, IReadOnlyList<IReadOnlyList<string>> rows)
    {
        _currentObject.Add("table", new JsonObject
        {
            ["headers"] = new JsonArray([.. headers.Select(h => (JsonNode)h)]),
            ["rows"] = new JsonArray([.. rows.Select(r => (JsonNode)new JsonArray([.. r.Select(c => (JsonNode)c)]))])
        });
    }

    public override string ToString()
    {
        return JsonSerializer.Serialize(_root, new JsonSerializerOptions { WriteIndented = true });
    }
}
