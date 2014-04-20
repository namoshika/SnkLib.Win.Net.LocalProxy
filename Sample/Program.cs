using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            var proxy = new SunokoLibrary.Net.NetServiceDaemon();
            proxy.Start(new SunokoLibrary.Net.HttpProxyService(8080));
            Console.ReadLine();
        }
    }
}
