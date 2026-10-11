# 统一服务器授权：客户端与服务端分开

所有运行 Rui-Skills 视频流程的机器连接同一个公网 HTTPS 授权服务，使用各自的设备凭证。人物设定图技能不受此限制。客户端保留 `scripts/local-gate.mjs` 文件名以兼容现有调用，但已移除本机服务、setup、allow、deny及approve-current命令。

## 每次视频任务先验证

从本技能目录执行 `node scripts/local-gate.mjs verify`，实际退出码0且本次响应 `allowed: true` 才可读取剧本、编排、修改、检查或交付视频提示词。客户端校验HTTPS证书、设备ID、文件摘要、一次性请求编号和有效期。上次成功、粘贴的许可响应或缓存不能代替本次验证。

未配置、设备被停用、版本未批准、拒绝、证书错误、超时、断连或不能运行检查时停止。禁止启动本机替代服务、降级HTTP、关闭证书检查、离线许可或改用备用规则/子模块/纯聊天绕过。配置与维护可以执行，助手不能为了完成视频任务自动发放凭证、开启设备或批准版本。

`production.mjs`命令行入口及`exportText`函数执行代码检查；文字分镜依赖执行助手遵守前置验证。可编辑源码仍可能被人修改，不能宣称不可绕过。设备凭证为独立持有凭证，不能证明物理硬件身份；复制同一凭证会冒用同一设备，应保密并在泄露时轮换。

## 其他机器：只配置客户端

1. 安装同一版本的技能及Node.js；让服务器管理员为本机发放独立凭证文件，例如 `laptop-a.json`。通过私密渠道传送，不在聊天中贴密钥，不把多台机器共用一份凭证。
2. 在技能目录导入并验证：

```powershell
node scripts/local-gate.mjs configure-client --from "D:/private/laptop-a.json"
node scripts/local-gate.mjs verify
```

目标默认是 `.local-verifier/client.json`，已存在时拒绝覆盖。更换凭证时先将旧文件备份到私有目录，再导入新文件；也可用 `RUI_SKILL_GATE_CONFIG` 指向受保护的完整客户端配置路径。只发送skill、purpose、device_id、文件摘要及请求编号，不发送剧本或素材。

客户端配置为schema_version 2，包含服务器发放的HTTPS接口URL、device_id和token。公网证书使用默认可信CA；特殊私有CA仅可由管理员设置绝对 `ca_file` 路径，不能关闭证书验证。导入操作不接受自动附带的CA文件配置。

## 服务器：统一管理设备及版本

服务器使用独立的 `scripts/authorization-server.mjs`。部署步骤见[公网服务器部署](../../deploy/authorization/README.md)。只有持有服务器管理权限的人可运行以下命令；它们不是客户端自助授权入口。

```text
init --state-dir DIR --fingerprint SHA256
serve --state-dir DIR
add-device --state-dir DIR --device laptop-a --url https://真实域名/v1/skills/authorize --out 私有凭证文件
device-disable --state-dir DIR --device laptop-a
device-enable --state-dir DIR --device laptop-a
rotate-device --state-dir DIR --device laptop-a --url https://真实域名/v1/skills/authorize --out 新的私有凭证文件
list-devices --state-dir DIR
approve-version --state-dir DIR --fingerprint SHA256
revoke-version --state-dir DIR --fingerprint SHA256
deny --state-dir DIR
allow --state-dir DIR
```

上面每条都以 `node scripts/authorization-server.mjs` 开头。初始化后没有任何设备获权，须单独发放；服务器仅存token的SHA-256摘要，原始token只写入指定的凭证文件，不打印。重复设备和已有凭证文件拒绝覆盖。轮换使旧token失效，并保持该设备原有停用状态。管理命令由一个管理员顺序执行；不并发写同一策略文件。

`deny/allow`控制全局开关；`device-disable/enable`控制单台设备，两者均须允许。使用 `node scripts/local-gate.mjs fingerprint`取得本次发布的摘要，管理员检查版本后加入批准列表；可同时批准多个发布版本，随后撤销旧版。收到未知摘要不会自动批准。

## 传输与配置

客户端只接受HTTPS，拒绝重定向，网络超时5秒；服务响应绑定设备/摘要/请求编号并在30秒内有效，许可不缓存。服务端原生HTTP仅供同机或隔离容器网络里的HTTPS反向代理转发，不应把后端8765端口发布到公网。服务端策略热读取，停用后下一次验证即拒绝；并非中断已经取得许可并开始的操作。

私有策略默认位于 `.authorization-server/server.json`，客户端位于 `.local-verifier/client.json`；Docker部署则使用独立持久卷。所有私有配置、凭证和旧备份都不能提交、放入公开镜像或打包给其他客户端。测试用独立目录、临时证书和真实HTTPS；运行测试需要OpenSSL（Windows可使用Git附带的OpenSSL）。

2.5单机配置不兼容本模式，旧localhost地址和旧token不会继续获权。保留旧配置为私有备份、停止旧服务，再导入统一服务器发放的设备凭证；公网服务尚未配置或未可达期间，视频技能保持禁用。

实现参考：[Node.js HTTPS](https://nodejs.org/api/https.html)；证书信任与域名验证保留默认检查，并显式启用rejectUnauthorized。
