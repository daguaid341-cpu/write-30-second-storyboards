# Rui-Skills 公网统一授权服务

此部署包尚需真实域名、公网服务器及管理访问权限。代码或本机TLS测试通过不等于公网部署完成。以下命令面向已安装Docker Engine与Compose的Linux服务器；客户端机器只导入其独立凭证，不运行本服务。

## 域名和端口

把专用授权域名的DNS A记录指向服务器；如配置AAAA，IPv6也必须可达。确保80/443端口由本包的Caddy使用并可从公网到达；已有网站占用时应并入既有反向代理，不停止其他服务。后端8765端口仅存在于隔离容器网络，没有映射到主机。

Caddy负责公网HTTPS及证书续期，证书数据保存在持久卷，见[官方自动HTTPS条件](https://caddyserver.com/docs/automatic-https)。仓库包含Dockerfile、compose.yaml、Caddyfile及不含密钥的.env.example；域名示例需替换，不能直接部署example.com。

## 首次部署

先在你已检查的完整技能副本中记录发布摘要：

```powershell
node rui-skills/scripts/local-gate.mjs fingerprint
```

在服务器获取同一提交的仓库，进入 `deploy/authorization`：

```bash
cp .env.example .env
# 编辑 .env，把 AUTH_DOMAIN 改为实际域名，不带 https:// 和路径
docker compose config --quiet
docker compose build authorization
docker compose run --rm authorization init --state-dir /state --fingerprint 这里替换为已核对的64位摘要
docker compose up -d
```

初始化不可覆盖现有策略，且不会自动发放任何设备凭证。服务启动后，从外部机器发起实际授权请求才能确认可用；浏览器GET接口返回404属于正常行为，不能据此判断授权通过。

## 为每台电脑发凭证

以laptop-a为例，替换真实域名；一个设备用一个ID与文件：

```bash
docker compose run --rm authorization add-device --state-dir /state --device laptop-a --url https://auth.example.com/v1/skills/authorize --out /exports/laptop-a.json
mkdir -p .private
chmod 700 .private
docker compose cp authorization:/exports/laptop-a.json .private/laptop-a.json
chmod 600 .private/laptop-a.json
```

通过受保护渠道把这一个文件交给对应电脑，不把服务端策略、其他机器凭证或整个卷一起复制。客户端在技能目录执行 `node scripts/local-gate.mjs configure-client --from 私有文件路径`，再执行 `verify`。公网证书、网络、设备开关和批准版本都通过才返回allowed。

凭证文件是明文秘密，只保存在管理员私有目录及目标机器；服务器策略只存摘要。分发完后可清理导出卷中的对应副本，但先确认目标机器已保存，不删除服务策略或证书卷。

## 停用、恢复和轮换

```bash
docker compose run --rm authorization list-devices --state-dir /state
docker compose run --rm authorization device-disable --state-dir /state --device laptop-a
docker compose run --rm authorization device-enable --state-dir /state --device laptop-a
docker compose run --rm authorization rotate-device --state-dir /state --device laptop-a --url https://auth.example.com/v1/skills/authorize --out /exports/laptop-a-v2.json
```

停用即时影响后续验证；轮换旧凭证失效，新凭证另行分发，设备原有停用状态保留。不要并发执行管理命令。全局停用用 `deny --state-dir /state`，恢复用 `allow --state-dir /state`。

## 发布新版

检查新版内容并取得完整客户端摘要后，运行：

```bash
docker compose run --rm authorization approve-version --state-dir /state --fingerprint 新版64位摘要
# 完成客户端迁移后再撤销旧版
docker compose run --rm authorization revoke-version --state-dir /state --fingerprint 旧版64位摘要
```

服务端容器只复制授权代码，不包含完整技能文本；不要用容器内文件计算客户端版本摘要。更新服务代码时重新构建并 `up -d`，保留策略和Caddy数据卷。不要运行 `docker compose down -v`，它会删除许可及证书数据。

## 已有反向代理

可以在服务器直接以Node运行authorization-server.mjs，默认后端监听127.0.0.1:8765；通过已有HTTPS代理转发POST `/v1/skills/authorize`，保留Authorization与X-Rui-Device请求头，不缓存响应。无需向公网开放管理接口，设备管理只通过服务器Shell进行。参考[Caddy reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)。

公网统一授权不把公开可编辑技能变成不可复制软件。若将来需要不可绕过的执行控制，应把关键生成能力放在服务器，客户端只请求结果；当前版本仍是使用许可检查。
