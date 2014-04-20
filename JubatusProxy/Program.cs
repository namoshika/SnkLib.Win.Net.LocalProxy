using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using SunokoLibrary.Net;

namespace JubatusProxy
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=============================================");
            Console.WriteLine("# DeviousServer");
            //Console.WriteLine("Description:\r\n\t当アプリを起動したPCをWebサーバー化して、アクセスされた際に渡されるRequestURIを指定したWebサーバーに対して放り投げるアプリです。その際にMessageHeaderを一部変更する事ができ、TeraTermやPuTTY等のSSHクライアントと併用する事でFWの向こうに存在するWebサーバーへ外部からアクセスする事が出来ます。");
            Console.WriteLine("=============================================");

            var proxy = new SunokoLibrary.Net.NetServiceDaemon();
            var overrideHeader = new System.Collections.Specialized.NameValueCollection();

            //起動に必須な情報を構成ファイルから読み込む
            Console.WriteLine("初期化用構成XMLパス(ex: initArgs.xml)");
            var fInfo = new System.IO.FileInfo(Console.ReadLine());
            var strmReader = fInfo.OpenText();
            var xml = System.Xml.Linq.XElement.Load(strmReader);
            //必須情報読み込み
            var forwardUrl = new Uri(xml.Element("forwardUrl").Value);
            var listenPort = int.Parse(xml.Element("listenPort").Value);
            foreach (var msgHeader in xml.Element("override").Elements("messageHeader"))
            {
                var key = msgHeader.Attribute("key").Value;
                var val = msgHeader.Value;
                overrideHeader.Add(key, val);
            }

            Console.WriteLine("\n--------------------Start--------------------");
            Console.WriteLine("ForwardUrl: {0}", forwardUrl);
            Console.WriteLine("ListenPort: {0}", listenPort);
            Console.WriteLine("Override");
            Console.WriteLine("   MessageHeader");
            foreach (var pair in overrideHeader.AllKeys)
                Console.WriteLine("   {0}: {1}", pair, overrideHeader[pair]);

            proxy.Start(new JubatusProxyService(forwardUrl, overrideHeader,
                System.Net.IPAddress.Loopback, listenPort));
            Console.ReadLine();
        }
    }
    public class JubatusProxyService : HttpService
    {
        public JubatusProxyService(Uri forwardUrl, NameValueCollection overrideHeader, IPAddress allow, int listenPort)
            : base(null, allow, listenPort)
        {
            ForwardUrl = forwardUrl;
            OverrideHeader = overrideHeader;

            OverrideHeader.Add("Host", "www.ne.senshu-u.ac.jp");
        }

        public Uri ForwardUrl { get; set; }
        public NameValueCollection OverrideHeader { get; set; }

        protected override void OnReceivedContext(ReceivedContextEventArgs e)
        {
            var req = WebRequest.Create(ForwardUrl + e.Context.Request.Url.OriginalString) as HttpWebRequest;
            req.Method = e.Context.Request.Method;
            SetMessageHeader(e.Context.Request.Headers, req);
            SetMessageHeader(OverrideHeader, req);

            try
            {
                var res = req.GetResponse();
                var resStrm = res.GetResponseStream();
                var outStrm = e.Context.Response.GetOutputStream();
                outStrm.Write(resStrm);
            }
            catch (WebException ex)
            {
                var res = (HttpWebResponse)ex.Response;
                if (res != null)
                {
                    e.Context.Response.ProtocolVersion = new Version("1.1");
                    e.Context.Response.StatusCode = res.StatusCode;
                    foreach (var str in res.Headers.AllKeys)
                    {
                        e.Context.Response.Headers[str] = ex.Response.Headers[str];
                    }
                    using (var outStrm = e.Context.Response.GetOutputStream())
                    {
                        using (var inStrm = res.GetResponseStream())
                        {
                            byte[] buffer2 = new byte[1024];
                            int num2 = 0;
                            while ((num2 = inStrm.Read(buffer2, 0, buffer2.Length)) > 0)
                            {
                                outStrm.Write(buffer2, 0, num2);
                            }
                        }
                        return;
                    }
                }
                e.Context.Response.StatusCode = HttpStatusCode.BadGateway;
            }
        }
        void SetMessageHeader(NameValueCollection headers, HttpWebRequest req)
        {
            foreach (string str in headers.AllKeys)
            {
                string value = headers[str];
                switch (str.ToLower())
                {
                    case "accept":
                        req.Accept = value;
                        break;
                    case "if-modified-since":
                        try
                        {
                            //req.IfModifiedSince = DateTime.ParseExact(value, @"ddd, dd MMM yyyy HH:mm:ss G\MT", CultureInfo.CreateSpecificCulture("en-US"));
                        }
                        catch (FormatException) { }
                        break;
                    case "connection":
                        //    if (value != "close")
                        //        req.Connection = value;
                        break;
                    case "content-length":
                        req.ContentLength = long.Parse(value);
                        break;
                    case "content-type":
                        req.ContentType = value;
                        break;
                    case "user-agent":
                        req.UserAgent = value;
                        break;
                    case "referer":
                        //req.Referer = value;
                        break;
                    case "proxy-connection":
                    case "host":
                    case "range":
                        break;
                    default:
                        req.Headers.Add(str, value);
                        break;
                }
            }
        }
    }
}
