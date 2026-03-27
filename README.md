# 快速启动

## 方案一：纯前端版本（仅展示，无代码执行）

直接用浏览器打开 `frontend/index.html` 即可。

```bash
cd frontend
python -m http.server 8080
# 然后访问 http://localhost:8080
```

特点：
- 零部署，开箱即用
- 攻击模拟在前端完成，仅供演示
- 适合了解漏洞原理

---

## 方案二：FastAPI + 前端（可真正执行代码）

需要安装依赖和Docker（用于沙箱隔离）：

```bash
cd full-stack/backend

# 安装Python依赖
pip install -r requirements.txt

# 确保Docker运行中
docker --version

# 启动服务
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
# 然后访问 http://localhost:8000
```

特点：
- 后端真正执行用户代码
- Docker沙箱隔离，安全可控
- 支持代码修改后实时验证
- 适合深入学习和实验

---

## 快速选择

| 场景 | 推荐方案 |
|------|---------|
| 仅浏览漏洞原理 | 纯前端版本 |
| 学习代码审计 | FastAPI版本 |
| 实验漏洞利用 | FastAPI版本 |
| 教学演示（无网络环境） | 纯前端版本 |
