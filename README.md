# websocket_lite

<h3>Websocket_Lite</h3>
<p>Linux/Mac <img src="https://travis-ci.org/smasherprog/websocket_lite.svg?branch=master"/><p>
<p>Windows <img src="https://ci.appveyor.com/api/projects/status/kqa94n7p8se05vi9/branch/master?svg=true"/><p>

<p>This library is intended to be a fully compliant websocket implementation <a href="http://htmlpreview.github.io/?https://github.com/smasherprog/websocket_lite/blob/master/Test/autobahn/index.html">Autobahn complete</a>, but with a few design goals:
<h2>No External Dependencies</h2>
<ul>
<li>
Cross-platform:Windows desktop, windows phone, Linux, Andriod, Mac desktop, iphone
</li>
<li>
Performance 
</li>
<li>
Encryption (openssl)
</li>
<li>
Extendable 
</li>
<li>
Latest standards: c++ 17 
</li>
</ul>
<h2>USAGE</h2>
<p>To get started check out the example here<p>
https://github.com/smasherprog/websocket_lite/blob/master/Test/main.cpp

```
    SL::WS_LITE::PortNumber port(3001);
    SL::WS_LITE::WSContext ctx(SL::WS_LITE::ThreadCount(1));
    auto listener = ctx.CreateListener(port);
    listener.onHttpUpgrade([&](const SL::WS_LITE::WSocket& socket) {
    
    });
    listener.onConnection([&](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
    
    });
    listener.onMessage([&](const SL::WS_LITE::WSocket& socket, const SL::WS_LITE::WSMessage& message) {
    
    });

    listener.startlistening();
    
    auto client = ctx.CreateClient();
    client.onHttpUpgrade([&](const SL::WS_LITE::WSocket& socket) {
    
    });
    client.onConnection([&](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
    
    });
    client.onDisconnection([&](const SL::WS_LITE::WSocket& socket, unsigned short code, const std::string& msg) {
    
    });
    client.connect("localhost", port);

```
