
# 关于

[![Build Status](https://travis-ci.com/zhbi98/SocksProxySever.svg?branch=master)](https://travis-ci.com/zhbi98/SocksProxySever)
![Lines of code](https://img.shields.io/tokei/lines/github/zhbi98/SocksProxySever)

这是一个使用 Java 实现的 Socks5 代理协议的服务器, 
这个代理服务器可直接运行于 windows 中, 目前已经在
Firefox 浏览器，微信，QQ 中测试通过。


# 运行环境

本项目主要用来研究 Socks 代理协议，该协议设计之初是为了让有权限的用户可以穿过内部局域网防火墙的限制，
来访问外部资源。本项目使用 NetBeans 配合 JDK 开发, NetBeans8.0 以及 JDK8.0 以上版本的均可以运行。
亦可使用其他集成开发环境, 例如 Eclipse, IntelliJ IDEA 配合使用 JDK8.0 以上版本均可构建此项目。

**使用注意事项：**

- 本项目的主方法位于 SocksProxySever.java 文件中。
- 如果需要使用请修改包的名称和路径，将包名称定义为你的包名和将文件放置于你的路径。


**其他集成开发环境下载链接：**
- [NetBeans download](https://netbeans.apache.org//)
- [Eclipse download](https://www.eclipse.org/downloads/)
- [IntelliJ download](https://www.jetbrains.com/zh-cn/idea/promo/)


# 更新日志
- 增加用户名密码认证登录。
- 修改用户名密码认证登录的逻辑问题。


# 许可证

本项目遵循 [MIT](https://opensource.org/licenses/MIT) 开源许可协议。

```
MIT License

Copyright (c) 2021 zhbi98

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```
