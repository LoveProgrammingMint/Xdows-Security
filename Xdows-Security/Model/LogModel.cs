using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using Microsoft.UI.Dispatching;

namespace Xdows_Security.Model
{
    public sealed class LogModel
    {
        private readonly ObservableCollection<string> _lines = new();
        private readonly DispatcherQueue _dq = DispatcherQueue.GetForCurrentThread();
        public ObservableCollection<string> Lines => _lines;

        private const int MAX_LINES = 200;

        public void Reload(string raw, string[]? filters)
        {
            _dq.TryEnqueue(() =>
            {
                var q = string.IsNullOrEmpty(raw)
                    ? Array.Empty<string>()
                    : raw.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

                if (filters?.Length > 0)
                    q = q.Where(l => filters.Any(f => l.Contains($"[{f}]"))).ToArray();

                _lines.Clear();
                foreach (var l in q.TakeLast(MAX_LINES))
                    _lines.Add(l);
            });
        }

        public void Push(string line)
        {
            _dq.TryEnqueue(() =>
            {
                if (_lines.Count >= MAX_LINES) _lines.RemoveAt(0);
                _lines.Add(line);
            });
        }

        public void Clear()
        {
            _dq.TryEnqueue(_lines.Clear);
        }

        public void Export(string path, string raw)
        {
            File.WriteAllText(path, raw);
        }
    }
}