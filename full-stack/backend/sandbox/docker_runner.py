"""
Docker沙箱代码运行器
在隔离的Docker容器中执行用户代码
"""

import asyncio
import docker
import uuid
import time
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class ExecutionResult:
    success: bool
    stdout: str
    stderr: str
    execution_time: float
    output_type: str  # normal, vulnerability_triggered, error


class DockerCodeRunner:
    """Docker沙箱代码运行器"""
    
    # 镜像映射
    IMAGE_MAP = {
        "python": "python:3.11-slim",
        "php": "php:8.2-cli",
        "go": "golang:1.21-alpine",
        "java": "openjdk:17-slim",
    }
    
    # 危险模式检测（用于演示漏洞触发）
    VULNERABILITY_PATTERNS = {
        "python": [
            ("os.system", "command-injection"),
            ("subprocess", "command-injection"),
            ("eval(", "code-injection"),
            ("exec(", "code-injection"),
            ("input(", "input-handling"),
        ],
        "php": [
            ("shell_exec", "command-injection"),
            ("exec(", "command-injection"),
            ("system(", "command-injection"),
            ("passthru", "command-injection"),
            ("eval(", "code-injection"),
        ],
        "java": [
            ("Runtime.getRuntime().exec", "command-injection"),
            ("ProcessBuilder", "command-injection"),
            ("eval(", "code-injection"),
        ],
        "go": [
            ("exec.Command", "command-injection"),
            ("os/exec", "command-injection"),
            ("eval", "code-injection"),
        ],
    }
    
    def __init__(self):
        try:
            self.client = docker.from_env()
            self.client.ping()
            print("Docker连接成功")
        except Exception as e:
            print(f"Docker连接失败: {e}")
            self.client = None
    
    async def run(
        self, 
        language: str, 
        code: str, 
        stdin: str = "",
        timeout: int = 30
    ) -> ExecutionResult:
        """在沙箱中执行代码"""
        
        if not self.client:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Docker服务不可用",
                execution_time=0,
                output_type="error"
            )
        
        start_time = time.time()
        container_id = None
        
        try:
            # 获取镜像
            image = self.IMAGE_MAP.get(language)
            if not image:
                return ExecutionResult(
                    success=False,
                    stdout="",
                    stderr=f"不支持的语言: {language}",
                    execution_time=0,
                    output_type="error"
                )
            
            # 生成唯一容器名
            container_name = f"ctf-sandbox-{uuid.uuid4().hex[:8]}"
            
            # 准备代码文件
            code_filename = self._get_code_filename(language)
            
            # 创建容器并执行
            container = self.client.containers.run(
                image,
                command="sleep infinity",
                detach=True,
                name=container_name,
                mem_limit="256m",
                cpu_period=100000,
                cpu_quota=50000,  # 50% CPU
                pids_limit=64,
                network_mode="none",  # 禁用网络
                read_only=True,
                security_opt=["no-new-privileges"],
            )
            
            container_id = container.id
            
            # 在容器中创建可写目录并写入代码
            exec_result = container.exec_run(
                f"sh -c 'mkdir -p /sandbox && echo \"{self._escape_code(code)}\" > /sandbox/{code_filename}'",
                demux=True
            )
            
            if exec_result[0] != 0:
                return ExecutionResult(
                    success=False,
                    stdout="",
                    stderr=f"写入代码失败: {exec_result[1].decode() if exec_result[1] else ''}",
                    execution_time=time.time() - start_time,
                    output_type="error"
                )
            
            # 执行代码
            run_cmd = self._get_run_command(language, code_filename, stdin)
            exec_result = container.exec_run(
                run_cmd,
                demux=True,
                workdir="/sandbox"
            )
            
            stdout, stderr = exec_result[0] or b"", exec_result[1] or b""
            stdout_str = stdout.decode('utf-8', errors='replace') if stdout else ""
            stderr_str = stderr.decode('utf-8', errors='replace') if stderr else ""
            
            execution_time = time.time() - start_time
            success = exec_result.exit_code == 0
            
            # 检测漏洞模式
            output_type = self._detect_vulnerability(language, code, stdout_str, stderr_str)
            
            return ExecutionResult(
                success=success,
                stdout=stdout_str,
                stderr=stderr_str,
                execution_time=execution_time,
                output_type=output_type
            )
            
        except Exception as e:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=str(e),
                execution_time=time.time() - start_time,
                output_type="error"
            )
            
        finally:
            # 清理容器
            if container_id:
                try:
                    container = self.client.containers.get(container_id)
                    container.stop(timeout=5)
                    container.remove(force=True)
                except Exception:
                    pass
    
    def _get_code_filename(self, language: str) -> str:
        """获取代码文件名"""
        filenames = {
            "python": "main.py",
            "php": "main.php",
            "go": "main.go",
            "java": "Main.java",
        }
        return filenames.get(language, "main.txt")
    
    def _get_run_command(self, language: str, filename: str, stdin: str) -> str:
        """获取运行命令"""
        if stdin:
            stdin_redirect = f"echo '{stdin}' | "
        else:
            stdin_redirect = ""
        
        commands = {
            "python": f"python3 /sandbox/{filename}",
            "php": f"php /sandbox/{filename}",
            "go": f"cd /sandbox && go run {filename}",
            "java": f"javac {filename} && java -cp /sandbox Main",
        }
        return stdin_redirect + commands.get(language, f"cat /sandbox/{filename}")
    
    def _escape_code(self, code: str) -> str:
        """转义代码中的特殊字符"""
        return code.replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
    
    def _detect_vulnerability(
        self, 
        language: str, 
        code: str, 
        stdout: str, 
        stderr: str
    ) -> str:
        """检测代码中是否包含漏洞模式"""
        patterns = self.VULNERABILITY_PATTERNS.get(language, [])
        
        for pattern, vuln_type in patterns:
            if pattern in code:
                return f"vulnerability_triggered:{vuln_type}"
        
        return "normal"


# 单例实例
_runner = None

def get_runner() -> DockerCodeRunner:
    global _runner
    if _runner is None:
        _runner = DockerCodeRunner()
    return _runner
