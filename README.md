# 🔐 PassCheck — 密码强度检查器

> 纯 Python 密码强度分析工具，检测常见弱密码模式，给出安全建议。零依赖。

## 安装

```bash
git clone https://github.com/One1turn/PassCheck.git
cd PassCheck
```

## 使用

```bash
# 交互模式（密码不会显示在终端）
python passcheck.py

# 直接检查
python passcheck.py 'MyP@ssw0rd123'

# 批量检查文件中的密码（每行一个）
python passcheck.py --file passwords.txt

# 只输出评分（适合脚本使用）
python passcheck.py 'MyP@ssw0rd123' --score-only
```

## 评分标准

| 评分 | 等级 | 说明 |
|------|------|------|
| 0-20 | 💀 极弱 | 几秒内破解 |
| 21-40 | 🔴 弱 | 几分钟内破解 |
| 41-60 | 🟡 中等 | 几小时内破解 |
| 61-80 | 🟢 强 | 需要数月 |
| 81-100 | 🛡️ 极强 | 实际无法破解 |

## 检查项

- ✅ 长度（≥8/12/16/20）
- ✅ 大小写字母混合
- ✅ 数字
- ✅ 特殊字符
- ✅ 不含常见弱密码（admin, 123456, password 等）
- ✅ 不含键盘连续序列（qwerty, asdf）
- ✅ 不含日期模式
- ✅ 不含重复字符
- ✅ 信息熵计算
- ✅ 估算破解时间

MIT License
