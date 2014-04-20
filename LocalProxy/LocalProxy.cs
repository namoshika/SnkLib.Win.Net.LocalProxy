using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace SunokoLibrary.Net
{
    public class NetServiceDaemon
    {
        public NetServiceDaemon(int timeout = 5000, int keepAliveTimeout = 1000)
        {
            _portTl = new Dictionary<int, TcpListener>();
            _portSrv = new Dictionary<int, HttpServiceBase>();
            _services = new List<HttpServiceBase>();
            DefaultTimeout = timeout;
            DefaultKeepAliveTimeout = keepAliveTimeout;
            ServicePointManager.DefaultConnectionLimit = 8;
        }

        Dictionary<int, TcpListener> _portTl;
        Dictionary<int, HttpServiceBase> _portSrv;
        List<HttpServiceBase> _services;
        public int DefaultKeepAliveTimeout { get; set; }
        public int DefaultTimeout { get; set; }
        public System.Collections.ObjectModel.ReadOnlyCollection<HttpServiceBase> Services
        {
            get { return _services.AsReadOnly(); }
        }

        public void Start(HttpServiceBase srv)
        {
            if (_portSrv.ContainsKey(srv.ListenPort))
                throw new ArgumentException("引数srvが使用するPortは既に使用されています。");

            var tl = new TcpListener(srv.Address, srv.ListenPort);
            _services.Add(srv);
            _portSrv.Add(srv.ListenPort, srv);
            _portTl.Add(srv.ListenPort, tl);
            
            tl.Start();
            tl.BeginAcceptTcpClient(new AsyncCallback(Callback_BeginAcceptTcpClient), srv.ListenPort);
        }
        public bool Stop(HttpServiceBase srv)
        {
            if (_services.Contains(srv))
                return false;

            _portSrv.Remove(srv.ListenPort);
            _portTl[srv.ListenPort].Stop();
            _portTl.Remove(srv.ListenPort);
            _services.Remove(srv);
            return true;
        }
        void ReceivedTcpClient(object[] arg)
        {
            var tc = arg[0] as TcpClient;
            var srv = arg[1] as HttpServiceBase;
            try
            {
                tc.ReceiveTimeout = srv.Timeout > -1 ? srv.Timeout : DefaultTimeout;
                var keepAlive = true;
                var netStrm = tc.GetStream();
                using (var strm = new System.IO.BufferedStream(netStrm))
                {
                    do
                    {
                        var context = new HttpContext(strm);
                        tc.ReceiveTimeout = srv.KeepAliveTimeout > -1 ? srv.KeepAliveTimeout : DefaultKeepAliveTimeout;
                        keepAlive = context.Request.KeepAlive;
                        try
                        {
                            srv.OnCalledService(context);
                        }
                        finally
                        {
                            context.Close();
                        }
                    }
                    while (keepAlive);
                }
            }
            //タイムアウト用
            catch (IOException e) { }
            //Connection: close用
            catch (InvalidDataException e) { }
            finally
            {
                tc.Close();
            }
        }
        void Callback_BeginAcceptTcpClient(IAsyncResult result)
        {
            var port = (int)result.AsyncState;
            var tl = _portTl[port];
            var srv = _portSrv[port];
            
            tl.BeginAcceptTcpClient(new AsyncCallback(Callback_BeginAcceptTcpClient), srv.ListenPort);
            var tc = tl.EndAcceptTcpClient(result);
            System.Threading.ThreadPool.QueueUserWorkItem(obj => ReceivedTcpClient(new object[] { obj, srv }), tc);
        }
    }
    public class HttpService : HttpServiceBase
    {
        public HttpService(ReceivedContextEventHandler handler, IPAddress allow, int listenPort)
            : base(allow, listenPort)
        {
            ReceivedContext = handler;
        }
        public override void OnCalledService(HttpContext context)
        {
            HttpWebResponse response = null;
            try
            {
                if (context.Request.Method == "CONNECT")
                    throw new IOException();
                var args = new ReceivedContextEventArgs(context);
                OnReceivedContext(args);
            }
            finally
            {
                if (response != null)
                {
                    response.Close();
                }
            }
        }

        public ReceivedContextEventHandler ReceivedContext;
        protected virtual void OnReceivedContext(ReceivedContextEventArgs e)
        {
            if (ReceivedContext != null)
                ReceivedContext(this, e);
        }
    }
    public class HttpProxyService : HttpServiceBase
    {
        public HttpProxyService(int listenPort)
            : base(IPAddress.Loopback, listenPort) { }
        public override void OnCalledService(HttpContext context)
        {
            HttpWebResponse response = null;
            try
            {
                if (context.Request.Method == "CONNECT")
                    throw new IOException();

                var writer = new HttpRequestWriter(context);
                using (var inStrm = writer.Response.GetResponseStream())
                using (var outStrm = context.Response.GetOutputStream())
                {
                    var buffer = new byte[5120];
                    var count = 0;
                    while ((count = inStrm.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        outStrm.Write(buffer, 0, count);
                    }
                }
            }
            catch (WebException exception)
            {
                var res = (HttpWebResponse)exception.Response;
                if (res != null)
                {
                    context.Response.ProtocolVersion = new Version("1.1");
                    context.Response.StatusCode = res.StatusCode;
                    foreach (var str in res.Headers.AllKeys)
                    {
                        context.Response.Headers[str] = exception.Response.Headers[str];
                    }
                    using (var outStrm = context.Response.GetOutputStream())
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
                context.Response.StatusCode = HttpStatusCode.BadGateway;
            }
            catch (IOException e) { }
            finally
            {
                if (response != null)
                {
                    response.Close();
                }
            }
        }

        public event ReceivedContextEventHandler PassingContext;
        protected void OnPassingContext(ReceivedContextEventArgs e)
        {
            if (PassingContext != null)
                PassingContext(this, e);
        }
    }

    public abstract class HttpServiceBase
    {
        public HttpServiceBase(IPAddress localAdres, int listenPort)
        {
            Address = localAdres;
            ListenPort = listenPort;
            Timeout = -1;
            KeepAliveTimeout = -1;
        }

        public IPAddress Address { get; protected set; }
        public int ListenPort { get; protected set; }
        public int KeepAliveTimeout { get; set; }
        public int Timeout { get; set; }

        public abstract void OnCalledService(HttpContext context);
    }
    public class HttpContext
    {
        public HttpContext(Stream strm)
        {
            Request = new HttpRequestReader(strm);
            Response = new HttpResponseWriter(strm);
        }

        public HttpRequestReader Request { get; private set; }
        public HttpResponseWriter Response { get; private set; }

        public void Close()
        {
            Request.Close();
            Response.Close();
        }
    }
    public class HttpRequestReader
    {
        public HttpRequestReader(Stream strm)
        {
            try
            {
                _strm = strm;
                _isClosed = false;
                _httpStrm = new HttpRequestStream(strm);
                Headers = new WebHeaderCollection();
                Cookies = new CookieContainer();
                ReadMessageHeader();
            }
            catch (Exception exception)
            {
                Close();
                throw exception;
            }
        }

        bool _isClosed;
        Stream _strm;
        HttpRequestStream _httpStrm;

        public WebHeaderCollection Headers { get; protected set; }
        public Version ProtocolVersion { get { return _httpStrm.RequestLine.ProtocolVersion; } }
        public string Method { get { return _httpStrm.RequestLine.Method; } }
        public Uri Url { get { return _httpStrm.RequestLine.Url; } }
        public long ContentLength { get { return _httpStrm.Length; } }
        public bool KeepAlive { get; protected set; }
        public string TransferEncoding { get; protected set; }
        public CookieContainer Cookies { get; protected set; }

        public Stream GetEntityStream() { return _httpStrm; }
        public void Close()
        {
            if (!_isClosed)
            {
                if (_httpStrm != null)
                    _httpStrm.Dispose();
                if (Headers != null)
                    Headers.Clear();
                _isClosed = true;
            }
            _strm = null;
            _isClosed = true;
        }
        void ReadMessageHeader()
        {
            //MessageHeader読み込み
            foreach (var pair in _httpStrm.Header)
            {
                var key = pair.Key;
                var val = pair.Value;
                switch (key.ToLower())
                {
                    case "connection":
                    case "proxy-connection":
                        KeepAlive = !(val.ToLower() == "close");
                        break;
                    case "cookie":
                        SetCookies(Cookies, val);
                        break;
                    case "transfer-encoding":
                        TransferEncoding = val.ToLower();
                        break;
                }
                Headers.Add(key, val);
            }
        }
        void SetCookies(CookieContainer cookies, string message)
        {
            try
            {
                if (message != null)
                    cookies.SetCookies(Url, message.Replace(";", ",").Trim());
            }
            catch (UriFormatException) { }
        }

        class HttpRequestStream : Stream
        {
            public HttpRequestStream(Stream strm)
            {
                _readLength = 0;
                _contentLength = 0;
                _strm = strm;
                Header = new Dictionary<string, string>();
                ReadHeader();
            }

            const int ASCII_CR = 13;
            const int ASCII_LF = 10;
            static int[] ASCII_CRLF = new int[] { 13, 10 };
            long _readLength, _contentLength;
            string _transferEncoding;
            Stream _strm;
            public HttpRequestLine RequestLine { get; protected set; }
            public Dictionary<string, string> Header { get; protected set; }

            void ReadHeader()
            {
                RequestLine = ReadRequestLine();
                if(RequestLine == null)
                    throw new InvalidDataException("HttpRequestヘッダーの書式に異常があります。");

                //MessageHeader読み込み
                while (true)
                {
                    var pair = ReadMessageHeader();
                    if (pair.Key == null)
                        break;
                    switch (pair.Key.ToLower())
                    {
                        case "content-length":
                            _contentLength = long.Parse(pair.Value);
                            break;
                        case "transfer-encoding":
                            _transferEncoding = "chunk";
                            break;
                    }
                    Header.Add(pair.Key, pair.Value);
                }
            }
            HttpRequestLine ReadRequestLine()
            {
                var str = ReadLine(_strm);
                var strArray = str.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (strArray.Length == 3)
                {
                    var line = new HttpRequestLine(
                        strArray[0].Trim(), strArray[1].Trim(),
                        new Version(strArray[2].Trim().Replace("HTTP/", "")));
                    return line;
                }
                else
                    return null;
            }
            KeyValuePair<string, string> ReadMessageHeader()
            {
                var str = ReadLine(_strm);
                var strArray = str.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
                if (strArray.Length < 2)
                    return new KeyValuePair<string, string>(null, null);

                var key = str.Substring(0, strArray[0].Length);
                var pair = new KeyValuePair<string, string>(key.Trim(), str.Substring(key.Length + 1).Trim());
                return pair;
            }
            string ReadLine(Stream strm)
            {
                using (var memStrm = new MemoryStream())
                using (var reader = new StreamReader(memStrm))
                {
                    var buffer = new byte[1];
                    var idx = 0;
                    while (strm.Read(buffer, 0, buffer.Length) > 0)
                    {
                        memStrm.WriteByte(buffer[0]);
                        if (buffer[0] == ASCII_CRLF[idx])
                        {
                            idx++;
                            if (idx == ASCII_CRLF.Length)
                                break;
                        }
                        else if (idx > 0)
                        {
                            idx = 0;
                        }
                    }
                    memStrm.Flush();
                    memStrm.Seek(0, SeekOrigin.Begin);
                    var line = reader.ReadToEnd();
                    return line;
                }
            }
            public override void Close()
            {
                var buffer = new byte[1024];
                while (Read(buffer, 0, buffer.Length) > 0) ;
            }
            public override void Flush()
            {
                _strm.Flush();
            }
            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_readLength >= _contentLength)
                    return 0;

                var cnt = (int)Math.Min(_contentLength - _readLength, (long)count);
                cnt = _strm.Read(buffer, offset, cnt);
                _readLength += cnt;
                return cnt;
            }
            public override bool CanRead { get { return this._strm.CanRead; } }
            public override bool CanSeek { get { return this._strm.CanSeek; } }
            public override bool CanWrite { get { return false; } }
            public override long Length
            {
                get
                {
                    if (_transferEncoding == "chunked")
                        throw new NotSupportedException("転送エンコーディングがChunk転送時はLengthを返すことはできません");
                    return _contentLength;
                }
            }
            public override long Position
            {
                get { return _strm.Position; }
                set { _strm.Position = value; }
            }
            public override int ReadTimeout
            {
                get { return _strm.ReadTimeout; }
                set { _strm.ReadTimeout = value; }
            }
            public override long Seek(long offset, SeekOrigin origin)
            {
                return _strm.Seek(offset, origin);
            }
            public override void SetLength(long value)
            {
                _strm.SetLength(value);
            }
            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException("このクラスは書き込みをサポートできません。");
            }
        }
        class HttpRequestLine
        {
            public HttpRequestLine(string method, string url, Version protocol)
            {
                Method = method;
                ProtocolVersion = protocol;
                Url = (url[0] != '/') ? new Uri(url) : new Uri(url, UriKind.Relative);
            }

            public string Method { get; private set; }
            public Version ProtocolVersion { get; private set; }
            public Uri Url { get; private set; }
        }
    }
    public class HttpRequestWriter : IDisposable
    {
        public HttpRequestWriter(HttpContext context)
        {
            Request = SetHeader(context);
            Response = GetHeader(context, Request);
        }

        public HttpWebRequest Request { get; protected set; }
        public HttpWebResponse Response { get; protected set; }

        public void Close()
        {
            if (Response != null)
                Response.Close();
        }
        public void Dispose()
        {
            Close();
        }
        HttpWebResponse GetHeader(HttpContext context, HttpWebRequest request)
        {
            var response = request.GetResponse() as HttpWebResponse;
            context.Response.ProtocolVersion = response.ProtocolVersion;
            context.Response.StatusCode = response.StatusCode;
            foreach (var str in response.Headers.AllKeys)
            {
                context.Response.Headers[str] = response.Headers[str];
            }
            return response;
        }
        HttpWebRequest SetHeader(HttpContext context)
        {
            var req = WebRequest.Create(context.Request.Url) as HttpWebRequest;
            req.Method = context.Request.Method;
            req.Timeout = 15000;
            SetMessageHeader(context.Request.Headers, req);
            if (context.Request.ContentLength <= 0)
                return req;

            var inputStream = context.Request.GetEntityStream();
            var requestStream = req.GetRequestStream();

            int cnt;
            var buffer = new byte[1024];
            for (var len = context.Request.ContentLength; len > 0; len -= cnt)
            {
                cnt = Math.Min(buffer.Length, (int)len);
                cnt = inputStream.Read(buffer, 0, cnt);
                requestStream.Write(buffer, 0, cnt);
            }
            return req;
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
                        catch (FormatException)
                        {
                        }
                        break;
                    case "connection":
                        if (value != "close")
                            req.Connection = value;
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
                        req.Referer = value;
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
    public class HttpResponseWriter
    {
        public HttpResponseWriter(Stream strm)
        {
            Headers = new WebHeaderCollection();
            ProtocolVersion = new Version(1, 1);
            StatusCode = HttpStatusCode.OK;
            _httpStrm = new HttpStreamWriter(strm);
            _isSentHeader = false;
        }

        bool _isSentHeader;
        WebHeaderCollection _headers;
        HttpStreamWriter _httpStrm;
        HttpStatusCode _status;
        Version _protocolVer;

        public long ContentLength
        {
            get
            {
                long len;
                len = long.TryParse(Headers[HttpRequestHeader.ContentLength], out len) ? len : -1;
                return len;
            }
            set
            {
                if (_isSentHeader)
                    throw new InvalidOperationException("GetOutputStreamの発動前に使いましょう。");
                Headers[HttpRequestHeader.ContentLength] = value.ToString();
            }
        }
        public WebHeaderCollection Headers
        {
            get { return _headers; }
            set
            {
                if (_isSentHeader)
                    throw new InvalidOperationException(
                        "GetOutputStreamの発動前に使いましょう。");
                _headers = value;
            }
        }
        public Version ProtocolVersion
        {
            get { return _protocolVer; }
            set
            {
                if (_isSentHeader)
                    throw new InvalidOperationException(
                        "GetOutputStreamの発動前に使いましょう。");

                _protocolVer = value;
            }
        }
        public HttpStatusCode StatusCode
        {
            get { return _status; }
            set
            {
                if (_isSentHeader)
                    throw new InvalidOperationException(
                        "GetOutputStreamの発動前に使いましょう。");
                _status = value;
            }
        }
        public string TransferEncoding
        {
            get
            {
                var str = Headers[HttpRequestHeader.TransferEncoding];
                return str == null ? string.Empty : str;
            }
            set
            {
                if (_isSentHeader)
                    throw new InvalidOperationException(
                        "GetOutputStreamの発動前に使いましょう。");
                Headers[HttpRequestHeader.TransferEncoding] = value;
            }
        }

        public void Close()
        {
            GetOutputStream();
            _httpStrm.Flush();
            _httpStrm.Close();
        }
        public HttpStreamWriter GetOutputStream()
        {
            if (!_isSentHeader)
            {
                _isSentHeader = true;
                if (ContentLength < 0)
                {
                    if (Headers[HttpRequestHeader.ContentLength] != null)
                        Headers.Remove(HttpResponseHeader.ContentLength);
                }

                _httpStrm.WriteStatusLine(ProtocolVersion, StatusCode);
                foreach (var str in Headers.AllKeys)
                {
                    _httpStrm.WriteHeader(str, Headers[str]);
                }
            }
            return _httpStrm;
        }

        public class HttpStreamWriter : Stream
        {
            static HttpStreamWriter()
            {
                ASCII_CRLF = new byte[] { 13, 10 };
            }
            public HttpStreamWriter(Stream strm)
            {
                _strm = strm;
                _position = HttpStreamPosition.None;
                _entityLength = 0;
                _contentLength = 0;
            }

            private long _contentLength;
            private long _entityLength;
            private bool _isChunked;
            private HttpStreamPosition _position;
            private Stream _strm;
            private const int ASCII_CR = 13;
            private const int ASCII_LF = 10;
            private static byte[] ASCII_CRLF;

            public override bool CanRead { get { return _strm.CanRead; } }
            public override bool CanSeek { get { return _strm.CanSeek; } }
            public override bool CanWrite { get { return _strm.CanWrite; } }
            public override long Length { get { return _entityLength; } }
            public override long Position
            {
                get { return _strm.Position; }
                set { this._strm.Position = value; }
            }

            public override void Close()
            {
                switch (_position)
                {
                    case HttpStreamPosition.None:
                        WriteStatusLine(new Version("1.1"), HttpStatusCode.Found);
                        break;
                    case HttpStreamPosition.StatusLine:
                        _strm.Write(ASCII_CRLF, 0, ASCII_CRLF.Length);
                        _position = HttpStreamPosition.Entity;
                        break;
                }

                if (!_isChunked)
                {
                    var buffer = new byte[1024];
                    int len;
                    for (var i = _contentLength - Length; i > 0; i -= len)
                    {
                        len = (int)Math.Min(buffer.Length, buffer.Length);
                        Write(buffer, 0, len);
                    }
                }
                else
                {
                    _strm.Write(Encoding.ASCII.GetBytes("0"), 0, 1);
                    _strm.Write(ASCII_CRLF, 0, ASCII_CRLF.Length);
                    _strm.Write(ASCII_CRLF, 0, ASCII_CRLF.Length);
                }
            }
            protected override void Dispose(bool disposing)
            {
                try
                {
                    Close();
                }
                finally
                {
                    base.Dispose(disposing);
                }
            }
            public override void Flush()
            {
                _strm.Flush();
            }
            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException("この動作はサポートされていません。");
            }
            public override long Seek(long offset, SeekOrigin origin)
            {
                return _strm.Seek(offset, origin);
            }
            public override void SetLength(long value)
            {
                _strm.SetLength(value);
            }
            public override void Write(byte[] buffer, int offset, int count)
            {
                if (_position == HttpStreamPosition.None)
                    throw new InvalidOperationException("リクエストヘッダの情報がセットされていません。");
                if (_position != HttpStreamPosition.Entity)
                    _strm.Write(ASCII_CRLF, 0, ASCII_CRLF.Length);
                _position = HttpStreamPosition.Entity;

                if (!_isChunked)
                    _strm.Write(buffer, offset, count);
                else
                {
                    var bytes = Encoding.ASCII.GetBytes(Convert.ToString(count, 16));
                    _strm.Write(bytes, 0, bytes.Length);
                    _strm.Write(ASCII_CRLF, 0, ASCII_CRLF.Length);
                    _entityLength += bytes.LongLength + ASCII_CRLF.LongLength;
                    _strm.Write(buffer, offset, count);
                    _strm.Write(ASCII_CRLF, 0, ASCII_CRLF.Length);
                    _entityLength += ASCII_CRLF.LongLength;
                }

                _entityLength += count;
            }
            public void Write(System.IO.Stream entity)
            {
                var buff = new byte[1024];
                var len = 0;
                while ((len = entity.Read(buff, 0, buff.Length)) > 0)
                {
                    Write(buff, 0, len);
                }
            }
            public void WriteHeader(string key, string value)
            {
                if (((key == "") || (key == null)) || (value == null))
                    throw new ArgumentNullException("引数にnullが入っています。変な物入れんなや糞");
                if (this._position != HttpStreamPosition.StatusLine)
                    throw new InvalidOperationException("ヘッダはリクエストラインを書き込んだ直後しか書き込めません。");

                var keyStr = key.ToLower();
                switch (keyStr)
                {
                    case "content-length":
                        _contentLength = long.Parse(value);
                        break;
                    case "transfer-encoding":
                        _isChunked = value == "chunked";
                        break;
                }

                var s = string.Format("{0}: {1}\r\n", key, value);
                var bytes = Encoding.ASCII.GetBytes(s);
                _strm.Write(bytes, 0, bytes.Length);
            }
            public void WriteStatusLine(Version version, HttpStatusCode status)
            {
                if (this._position != HttpStreamPosition.None)
                    throw new InvalidOperationException(
                        "リクエストラインを書き込みは初期化後の何もしていない状態でのみ可能です。");

                var s = string.Format("HTTP/{0} {1} {2}\r\n", version.ToString(), (int)status, status.ToString());
                var bytes = Encoding.ASCII.GetBytes(s);
                _position = HttpStreamPosition.StatusLine;
                _strm.Write(bytes, 0, bytes.Length);
            }

            private enum HttpStreamPosition
            {
                None,
                StatusLine,
                Entity,
                Invalid
            }
        }
    }
    public enum CancelOption
    {
        None,
        ChangeStream
    }

    public delegate void ReceivedContextEventHandler(object sender, ReceivedContextEventArgs e);
    public class ReceivedContextEventArgs : EventArgs
    {
        public ReceivedContextEventArgs(HttpContext context)
        {
            Context = context;
        }
        public HttpContext Context { get; private set; }
    }
}
