> ⚠️ **重要提示**
> 本项目已归档，推荐使用更便捷的替代方案，详情如下：
> 
> ⚠️ 项目归档
> 
> **状态：已归档，不再维护**
> 
> 鉴于 [腾讯云 EdgeOne](https://cloud.tencent.com/product/edgeone) 现已支持直接回源 **仅 AAAA 解析的域名**，推荐采用以下更简洁且易维护的方案替代本项目：
> 
> 1. 设置一个域名作为回源域名，使用 DDNS 服务动态更新域名解析记录。
> 2. 将该域名直接配置为 EdgeOne 的源站地址。
> 
> 本项目已完成其历史使命，现归档仅作参考。项目将不再接受新的 Issue 或 Pull Request。


# EdgeOne Dynamic Origin

EdgeOne 是腾讯云的边缘安全加速平台。该脚本为其提供动态更新源站组 IP 的功能。
此功能特别适用于那些 IP 地址可能会变化的源站，确保 CDN 始终能够正确地获取最新的内容。比如仅有动态 IPV6 地址的服务器，
也能够长期稳定部署WEB服务，而不必使用 frp / ngork 等内网端口转发工具。

注意，若要使用该脚本，在 EdgeOne 中的加速域名必须使用源站组配置源站。

### 使用方法

#### windows
1. 安装 `pip install eodo`
2. 运行 `eodo -p 54321`以启动。 -p 54321 表示 web 管理界面监听端口为 54321。
3. 在 `http://localhost:54321` 中配置必要的配置项。

#### ubuntu
1. 安装 `pip3 install eodo -U --break-system-packages`
2. 运行 `export PATH="$HOME/.local/bin:$PATH" && source ~/.bashrc` 将 ~/.local/bin 加入 PATH
3. 运行 `eodo -p 54321`以启动。  -p 54321 表示 web 管理界面监听端口为 54321。
4. 在 `http://localhost:54321` 中配置必要的配置项。

#### Docker
1. 构建镜像：
   ```bash
   docker build -t eodo:latest .
   ```
2. 运行容器：
   ```bash
   docker run -d --network=host --name eodo eodo:latest
   ```
3. 浏览器访问 `http://localhost:54321` 进行配置。

### WEB 界面
![img.png](img.png)

#### 说明

持久化运行可用 nssm 或 systemd 配置服务。
