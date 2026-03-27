"""
CTF-Web 漏洞学习平台 - FastAPI 后端
提供代码执行API和漏洞数据管理
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict
import json
import asyncio
import uuid
from datetime import datetime

from .sandbox.docker_runner import DockerCodeRunner

app = FastAPI(title="CTF-Web API", version="1.0.0")

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 代码运行器
code_runner = DockerCodeRunner()

# 加载漏洞数据
with open("frontend/assets/js/vulnerabilities.json", "r", encoding="utf-8") as f:
    vulnerability_data = json.load(f)


# ============ 数据模型 ============

class CodeExecutionRequest(BaseModel):
    language: str  # java, php, python, go
    code: str
    stdin: Optional[str] = ""
    timeout: Optional[int] = 30


class CodeExecutionResponse(BaseModel):
    success: bool
    stdout: str
    stderr: str
    execution_time: float
    output_type: str  # normal, vulnerability_triggered, error


class Vulnerability(BaseModel):
    id: str
    name: str
    name_en: str
    difficulty: str
    icon: str
    description: str
    color: str
    tags: List[str]


class AttackTestRequest(BaseModel):
    vulnerability_id: str
    payload: str


class AttackTestResponse(BaseModel):
    success: bool
    message: str
    data: Optional[str] = None
    mitigation_suggestions: List[str] = []


# ============ API路由 ============

@app.get("/")
async def root():
    return {"message": "CTF-Web API", "version": "1.0.0"}


@app.get("/api/vulnerabilities")
async def get_vulnerabilities():
    """获取所有漏洞列表"""
    return vulnerability_data["vulnerabilities"]


@app.get("/api/vulnerabilities/{vuln_id}")
async def get_vulnerability(vuln_id: str):
    """获取指定漏洞详情"""
    details = vulnerability_data["vulnerability_details"].get(vuln_id)
    if not details:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    return details


@app.post("/api/execute", response_model=CodeExecutionResponse)
async def execute_code(request: CodeExecutionRequest, background_tasks: BackgroundTasks):
    """
    在沙箱中执行代码
    """
    try:
        result = await code_runner.run(
            language=request.language,
            code=request.code,
            stdin=request.stdin,
            timeout=request.timeout
        )
        return result
    except Exception as e:
        return CodeExecutionResponse(
            success=False,
            stdout="",
            stderr=str(e),
            execution_time=0,
            output_type="error"
        )


@app.post("/api/test-attack", response_model=AttackTestResponse)
async def test_attack(request: AttackTestRequest):
    """
    测试攻击payload
    """
    vuln_id = request.vulnerability_id
    payload = request.payload
    
    # 预定义的payload检测
    payload_results = {
        "sqli": {
            "admin' OR '1'='1' --": {
                "success": True,
                "message": "SQL注入成功！使用 OR 1=1 恒真条件绕过了密码验证",
                "data": "用户列表: admin, user1, user2"
            },
            "default": {
                "success": False,
                "message": "未检测到SQL注入，请输入有效的payload",
                "data": None
            }
        },
        "xss": {
            "<script>alert('XSS')</script>": {
                "success": True,
                "message": "XSS攻击成功！恶意脚本已被执行",
                "data": "Cookie: session=stolen_by_xss"
            },
            "<img src=x onerror=alert(1)>": {
                "success": True,
                "message": "XSS攻击成功！使用img标签触发onerror",
                "data": "Cookie: session=stolen_by_xss"
            },
            "default": {
                "success": False,
                "message": "未检测到XSS攻击，请输入XSS payload",
                "data": None
            }
        },
        "command-injection": {
            "8.8.8.8; cat /etc/passwd": {
                "success": True,
                "message": "命令注入成功！成功读取/etc/passwd文件",
                "data": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon..."
            },
            "default": {
                "success": False,
                "message": "未检测到命令注入，请输入payload",
                "data": None
            }
        },
        "ssrf": {
            "http://169.254.169.254/latest/meta-data/": {
                "success": True,
                "message": "SSRF攻击成功！成功访问AWS元数据服务",
                "data": "ami-id: ami-12345678\ninstance-type: t2.micro"
            },
            "default": {
                "success": False,
                "message": "请输入SSRF payload",
                "data": None
            }
        },
        "xxe": {
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>": {
                "success": True,
                "message": "XXE攻击成功！外部实体被解析",
                "data": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon..."
            },
            "default": {
                "success": False,
                "message": "请输入XXE payload",
                "data": None
            }
        }
    }
    
    results = payload_results.get(vuln_id, payload_results.get("sqli", {}))
    return results.get(payload, results["default"] if "default" in results else {"success": False, "message": "未知漏洞类型", "data": None})


# ============ 前端静态文件服务 ============

@app.get("/favicon.ico")
async def favicon():
    return FileResponse("frontend/assets/img/favicon.ico")


@app.get("/assets/{path:path}")
async def serve_assets(path: str):
    return FileResponse(f"frontend/assets/{path}")


@app.get("/vulnerability/{vuln_id}/{path:path}")
async def serve_vulnerability_assets(vuln_id: str, path: str):
    return FileResponse(f"frontend/vulnerability/{vuln_id}/{path}")


@app.get("/vulnerability/{vuln_id}")
async def serve_vulnerability_page(vuln_id: str):
    return FileResponse(f"frontend/vulnerability/{vuln_id}/index.html")


@app.get("/index.html")
@app.get("/index")
async def serve_index():
    return FileResponse("frontend/index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
