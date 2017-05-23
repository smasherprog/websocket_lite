# websocket_lite

<h3>Websocket_Lite</h3>
<p>Linux/Mac <img src="https://travis-ci.org/smasherprog/websocket_lite.svg?branch=master"/><p>
<p>Windows <img src="https://ci.appveyor.com/api/projects/status/kqa94n7p8se05vi9/branch/master?svg=true"/><p>

<p>This library is intended to be a fully compliant websocket implementation, but with a few design goals:
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
https://github.com/smasherprog/websocket_lite/blob/master/Test/main.cpp#L44

```

    auto listener = SL::WS_LITE::WSListener::CreateListener(3002);
    listener.onHttpUpgrade([](const SL::WS_LITE::WSocket& socket) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onHttpUpgrade");
    });
    listener.onConnection([](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onConnection");
    });
    listener.onDisconnection([](const SL::WS_LITE::WSocket& socket, unsigned short code, const std::string& msg) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onDisconnection");
    });
    listener.startlistening();

    //auto client = SL::WS_LITE::WSClient::CreateClient(TEST_CERTIFICATE_PUBLIC_PATH);
    auto client = SL::WS_LITE::WSClient::CreateClient();
    client.onHttpUpgrade([](const SL::WS_LITE::WSocket& socket) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "Client::onHttpUpgrade");

    });
    client.onConnection([](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "Client::onConnection");
    });
    client.onDisconnection([](const SL::WS_LITE::WSocket& socket, unsigned short code, const std::string& msg) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "client::onDisconnection");
    });
    client.connect("localhost", 3002);


```
