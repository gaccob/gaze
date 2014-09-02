gaze
====

##### gaze是什么
gaze是一个命令行下的轻量级网络包监听工具, 有颜色显示, 跨平台(linux & windows), 支持TCP协议, 支持自定义插件.

* * *

##### 为什么不使用wireshark或者tcpdump:
* 跨平台, 使用了winpcap和libpcap, gaze是一个跨平台的实现, windows下用mingw编译, 方便前后端同事开发联调.
* 轻量, 整个代码除去了少量的第三方库, 也就1600行代码, 定制方便.
* 插件化开发接口简单, 只要根据业务需要实现导出的4个接口.

* * *
 
##### gaze启动参数
>   --tcp              "tcp packets"   
    --udp              "udp packets"   
    --eth      <name>  "device name, default use first eth device"   
    --plugin   <name>  "plugin shared library name"   
    --ip       <ip address>   
    --debug            "print ip & tcp level debug info"   
    --port     <port>   
    --help             "show usage"   
    
为什么没有使用libpcap或者说tcpdump的谓词语法, 纯粹只是使用习惯的问题, 更习惯linux的风格.
例如业务开发的插件是polar.dll, server的监听地址是tcp://10.1.164.54:7000, 可以用下面的命令来监听:
> ./gaze --tcp --port 7000 --ip 10.1.164.54 --plugin polar.dll

如果本地是多网卡的话, 并且需要监听的网卡不是默认的, 则可以用下面的命令来查看所有网卡设备：
> ./gaze --eth 

在linux下监听需要以root启动gaze.

* * *

##### 业务插件开发
如上面usage所示, 业务可以制定一个plugin参数, 这个plugin实际上是实现了下面接口(按需)的动态链接库, 进而解析解析业务的自定义协议. (link_key_t的类型在gaze.h中定义)
* void OnSend(link_key_t* key, const char* buffer, int len);   
* void OnRecv(link_key_t* key, const char* buffer, int len);   
* void OnBuild(link_key_t* key);   
* void OnFinish(link_key_t* key);   
需要注意的是, 为了保证跨平台可用, 我们需要将插件分别在linux下编译成so, 在windows下编译成dll.

* * *

##### 最后
这个工具的初衷是为了业务联调提高效率, 是在断断续续的工作之余完成的, 难免会有bug和各种todo, 请善待。 非常欢迎一起完善它.
