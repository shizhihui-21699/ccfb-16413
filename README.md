# invite-guard

日历邀请钓鱼（calendar-invite phishing）的投递前防护。纯 Python 标准库，无第三方依赖。

攻击链路很短：邮件带一个 `text/calendar` 部件 → 客户端**自动**把会议写进日程（收件人还没点任何东西）→ 地点/描述里塞着钓鱼链接和假的视频会议入口 → 到点弹出提醒 → 员工在"该参加会议了"的心理状态下点进去。传统邮件网关只看正文和附件，看不到 `LOCATION`、`CONFERENCE`、`X-MICROSOFT-SKYPETEAMSMEETINGURL`、`VALARM` 这些字段，而攻击的全部杀伤力恰恰在这些字段里。

本组件在**投递前**解析邀请的每一个字段，识别可疑的外部会议，把它降级为"待确认"再交给日历客户端。

---

## 设计要点

### 1. 不是拦掉，是"投递但解除武装"

| 判定 | 含义 | 处理 |
|---|---|---|
| `ALLOW` | 内容干净 | **原始字节**透传，一个字节都不改 |
| `PENDING` | 可疑的外部会议（如短链、陌生供应商） | 投递，但改为 `TENTATIVE` + 标题加 `[⚠ 待确认]`、删除 `VALARM`、链接去活化 |
| `QUARANTINE` | 存在硬冒犯信号（仿冒域名、同形字、用户信息欺骗等） | 不进任何人的日历，交安全复核队列 |
| `REJECT` | 已确认的恶意载荷（可执行附件、冒充本组织内部身份） | 整封丢弃，日历部件替换成说明文本 |

"待确认"是关键：真实外部客户会议数量巨大，**一刀切拦截会立刻被业务投诉到关停**。降级让会议仍出现在日程里（不误事），但把"一键加入"变成"请先向组织者核实"。

### 2. 硬信号一票否决，软信号累积

- 硬信号（`hard=True`，权重 100）单独就能定性：锚文本撒谎、`userinfo` 伪装（`teams.microsoft.com@evil.cn`）、同形字域名、品牌当子域名（`teams.microsoft.com.secure-join.cn`）、内部身份伪造、可执行附件……
- 软信号（陌生外部组织者 8 分、`http://` 8 分、高风险 TLD 20 分……）累加到 40 才降级。
- **已知客户只降敏、不免罪**：白名单域名给 20 分宽容度，但永远压不过硬信号（有测试保证）。

### 3. 各家日历格式差异用"链接槽位"抹平

同一个 Zoom 会议在不同客户端里可能是 `LOCATION`、`URL`、`CONFERENCE`、`X-ZOOM-MEETING-URL`、或只在描述正文里。检测器不针对客户端写分支，而是把所有链接来源归一成 `LinkSlot(prop, value, source)`，交给统一 URL 层判断。已覆盖的厂商属性：

```
URL / CONFERENCE / ATTACH
X-MICROSOFT-SKYPETEAMSMEETINGURL / X-MICROSOFT-SKYPETEAMSPROPERTIES
X-MICROSOFT-ONLINEMEETINGCONFLINK
X-GOOGLE-CONFERENCE / X-ZOOM-MEETING-URL / X-WEBEX-MEETING-URL
X-TENCENT-MEETING-URL / X-FEISHU-MEETING-URL / X-DINGTALK-MEETING-URL
X-APPLE-STRUCTURED-LOCATION / X-ALT-DESC / DESCRIPTION / LOCATION / SUMMARY
```

`CONFERENCE;FEATURE=PHONE` 被正确识别为拨入号码而非可点链接，`X-MICROSOFT-SKYPETEAMSPROPERTIES` 里的 JSON 不会被当成 URL 误报。

### 4. 更新/取消邀请的滥用

无状态检测看不到"这封邮件和上一封的关系"，而这正是更新/取消滥用的核心。`TrustStore` 记录每个 `UID` 的组织者、`SEQUENCE`、`DTSTAMP`、链接主机：

- **取消一封从未见过的会议** → `invite.cancel_no_history`
- **同一 UID 换了组织者** → `invite.uid_reused`（硬信号）
- **`SEQUENCE` 回退** → `invite.sequence_regression`（很多客户端仍会应用）
- **取消通知里带活动链接/附件** → 恶意取消，本身就是诱饵
- **`RRULE` 播种** → `invite.recurring_seed`：提醒会在此后一年反复触发，邮件早被遗忘

存储是单个 JSON 文件、原子替换、容量有界；读失败一律退化为"无记忆"，绝不阻塞邮件。

### 5. 域名可比对，且不会自伤

内嵌精简的公共后缀表（含 `co.uk`/`com.cn` 等多段后缀和 `sharepoint.com`/`github.io` 等私有后缀），保证：

- `contoso.sharepoint.com` 与 `evil.sharepoint.com` 是**两个不同**的可注册域（不会把租户混为一谈）
- `us02web.zoom.us` 属于 `zoom.us`，不误报
- `teams.microsoft.com.secure-join.cn` 的可注册域是 `secure-join.cn` → 品牌出现在子域名里

同形字/仿冒识别覆盖 Unicode 同形字、punycode、leet 替换、编辑距离 typo、`brand-login` 组合欺骗，并对**品牌名本身**做了归一化对称性处理（`office365` 不会被自己误判为仿冒 `office365`）。

### 6. 改写后仍是合法 iCalendar

降级输出折行至 75 octet、正确转义 `TEXT` / 参数、保留原 `VCALENDAR` 与未知属性。链接去活化用 `hxxps[://]host[.]tld` 形式，既不可点又可搜索。可信厂商的真实链接（如 `us02web.zoom.us`）**在降级邀请里仍然保留为可用 `URL`**——混合型邀请里不该连真会议一起废掉。

---

## 用法

### 作为库

```python
from invite_guard import process, MailContext

result = process(
    raw_ics_or_eml_bytes,
    mail=MailContext(from_address="cfo@contoso-finance.com"),
)
result.assessment.disposition   # Disposition.PENDING / QUARANTINE / REJECT / ALLOW
result.assessment.signals       # 每个信号带 code / weight / detail / hard，可直接进告警
result.output                   # 改写后的字节；REJECT 时为 None
```

### MIME（网关真实入口）

```python
from invite_guard import mime

result = mime.process_message(raw_eml, mail=MailContext(...))
result.worst                    # 整封邮件里最严重的判定
out = mime.flatten(result)      # 干净邮件原样返回原字节
```

### 命令行

```bash
# 扫描单个邀请
python -m invite_guard scan invite.ics \
  --from-address cfo@contoso-finance.com \
  --auth-header "spf=pass dkim=pass dmarc=pass"

# 网关过滤器：stdin 读邮件，stdout 出邮件；退出码即动作
python -m invite_guard filter --verdict verdicts.jsonl < message.eml > rewritten.eml
# 0 = 投递, 10 = 转复核, 20 = 丢弃
```

接入 Postfix：`content_filter` / milter 调 `filter`，按退出码决定 `DELIVER`/`HOLD`/`DISCARD`。

### 组织策略

```python
from invite_guard import Organisation, Policy

policy = Policy(org=Organisation(
    name="Example Corp",
    domains={"example.com", "example.cn"},
    own_brands={"examplecorp": {"examplecorp", "example-corp"}},
))
```

`TrustStore(path)` 持久化已知客户与 UID 历史；`store.allow_domains` 由管理员维护。

---

## 模块

| 文件 | 职责 |
|---|---|
| `ical.py` | 容错、有界的 RFC 5545 解析/序列化（折行、转义、嵌套、大小/深度上限） |
| `domains.py` | 可注册域、IDN/punycode、同形字折叠、仿冒检测 |
| `urls.py` | 从各字段抽 URL、HTML 锚文本、跳转解包、结构性欺骗识别 |
| `policy.py` | 组织/厂商/邮箱/高风险 TLD 策略；品牌令牌表 |
| `model.py` | 把各家客户端的邀请归一成 `Invite` 与链接槽位 |
| `auth.py` | 解析 `Authentication-Results`，SPF/DKIM/DMARC 与头域一致性 |
| `risk.py` | 信号、评分、分级处置、跨邮件历史判定、结果记录 |
| `sanitize.py` | 降级改写：待确认标记、链接去活化、删除提醒、附件处置 |
| `trust.py` | UID/域名记忆的 JSON 存储，原子写、有界、失败降级 |
| `mime.py` | 在 MIME 树里定位并改写日历部件；干净邮件原字节透传 |
| `cli.py` | `scan` / `filter` 两种模式 |

---

## 测试

```bash
python3 -m unittest discover -s tests -t .
```

121 个测试，分五组：

- `test_ical.py` — 解析与序列化不变量（折行按 UTF-8 字节、转义往返、深度/大小上限、UTF-16、裸 VEVENT）
- `test_domains_urls.py` — 可注册域、同形字、仿冒、锚文本、跳转解包
- `test_detection.py` — 样本库驱动：**8 个真实客户邀请（含飞书/钉钉/腾讯会议/纯 CONFLINK 格式）必须 ALLOW，16 个攻击变体必须全部拦下**，并检查硬信号的*种类*而不只是"拦住了"
- `test_sanitize_trust.py` — 降级改写产物合法、无残留可点链接、跨邮件历史
- `test_mime.py` / `test_cli.py` — MIME 定位改写、原字节透传、退出码

样本库在 `samples/`，新增真实误报样本是最便宜的回归手段。

---

## 已知边界

- **不做 DNS/信誉查询**：完全离线、确定性，适合高吞吐。真实部署可在 `analyze_link` 里挂可信的 URL 信誉服务。
- **不展开 `RRULE`**：只看单封邀请的结构信号，不需要展开。
- **VTIMEZONE 不解析**：时间语义对判定无关。
- **同形字表非穷举**：覆盖常见西里尔/希腊/全角映射；生产环境建议换用完整 confusables 表。
- **二进制附件的类型识别是魔数嗅探**，不是完整文件格式分析。
- 品牌令牌表 (`GLOBAL_BRAND_TOKENS`) 需按组织实际使用的协作平台调整，这是**误报率的主要旋钮**。
