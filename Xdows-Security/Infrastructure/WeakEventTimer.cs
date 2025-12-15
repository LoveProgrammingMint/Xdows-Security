using Microsoft.UI.Dispatching;
using System;

namespace Xdows_Security.Infrastructure
{
    public sealed class WeakEventTimer
    {
        private readonly DispatcherQueueTimer _timer;
        public event EventHandler<object?>? Tick;

        public WeakEventTimer(TimeSpan interval)
        {
            _timer = DispatcherQueue.GetForCurrentThread().CreateTimer();
            _timer.Interval = interval;
            _timer.Tick += (_, e) => Tick?.Invoke(this, e);
        }
        public void Start() => _timer.Start();
        public void Stop() => _timer.Stop();
    }
}