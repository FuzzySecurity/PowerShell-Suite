// Stephen Toub

using System;
using System.Runtime.InteropServices;

namespace FileOperation
{
    class ComReleaser<T> : IDisposable where T : class
    {
        private T _obj;

        public ComReleaser(T obj)
        {
            if (obj == null) throw new ArgumentNullException("obj");
            if (!obj.GetType().IsCOMObject) throw new ArgumentOutOfRangeException("obj");
            _obj = obj;
        }

        public T Item { get { return _obj; } }

        public void Dispose()
        {
            if (_obj != null)
            {
                Marshal.FinalReleaseComObject(_obj);
                _obj = null;
            }
        }
    }
}
