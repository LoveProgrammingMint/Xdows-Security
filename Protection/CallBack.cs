using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Xdows.Protection
{
    public static class CallBack
    {
        public delegate void InterceptCallBack(bool isSucceed, string path);
    }
}
