// Common utility functions for vulnerability pages

const VulnerabilityUtils = {
    // Get URL parameter
    getUrlParam(param) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(param);
    },

    // Format code with syntax highlighting (先高亮再转义)
    highlightCode(code, language) {
        // Keywords definition
        const keywords = {
            'java': ['public', 'private', 'protected', 'class', 'interface', 'extends', 'implements', 'static', 'final', 'void', 'int', 'String', 'boolean', 'if', 'else', 'for', 'while', 'return', 'new', 'try', 'catch', 'throw', 'throws', 'import', 'package'],
            'php': ['function', 'class', 'public', 'private', 'protected', 'if', 'else', 'foreach', 'while', 'return', 'echo', 'new', 'try', 'catch', 'throw', 'extends', 'implements', 'namespace', 'use', 'as', 'isset', 'unset', 'die', 'exit'],
            'python': ['def', 'class', 'if', 'elif', 'else', 'for', 'while', 'return', 'import', 'from', 'as', 'try', 'except', 'raise', 'with', 'lambda', 'yield', 'pass', 'break', 'continue', 'and', 'or', 'not', 'in', 'is', 'True', 'False', 'None', 'self'],
            'go': ['func', 'package', 'import', 'var', 'const', 'type', 'struct', 'interface', 'if', 'else', 'for', 'range', 'switch', 'case', 'default', 'return', 'go', 'defer', 'select', 'chan', 'map', 'make', 'new', 'nil', 'true', 'false']
        };

        // Process line: highlight keywords, strings, comments
        let processed = this.escapeHtml(code);

        // Highlight strings first (to protect them from keyword replacement)
        processed = processed.replace(/(&quot;|&apos;|&lt;|&gt;)|(&quot;)(?:(?!2)[^\\]|\\.)*\2|(&apos;)(?:(?!3)[^\\]|\\.)*\3|`(?:[^\\`]|\\.)*`/g, (match) => {
            return '<span class="text-green-400">' + match + '</span>';
        });

        // Unescape the string spans back (we don't want to escape content inside strings)
        processed = processed.replace(/&lt;span class="text-green-400"&gt;/g, '<span class="text-green-400">');
        processed = processed.replace(/&lt;\/span&gt;/g, '</span>');

        // Highlight comments
        processed = processed.replace(/(\/\/[^\n]*|\#[^\n]*)/g, '<span class="text-gray-500">$1</span>');

        // Highlight keywords (word boundary, not inside tags)
        const langKeywords = keywords[language] || keywords['java'];
        langKeywords.forEach(kw => {
            const regex = new RegExp('\\b(' + kw + ')\\b', 'g');
            processed = processed.replace(regex, '<span class="text-purple-400">$1</span>');
        });

        return processed;
    },

    // Escape HTML special characters
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    },

    // Render code with line numbers
    renderCode(code, highlightLines = []) {
        const lines = code.split('\n');
        return lines.map((line, idx) => {
            const lineNum = idx + 1;
            const isHighlight = highlightLines.includes(lineNum);
            const highlightClass = isHighlight ? 'highlight' : '';
            return `
                <div class="code-line ${highlightClass}">
                    <span class="code-line-number">${lineNum}</span>
                    <span class="code-line-content">${this.highlightCode(line, currentLanguage)}</span>
                </div>
            `;
        }).join('');
    },

    // Language display names
    languageNames: {
        'java': 'Java',
        'php': 'PHP',
        'python': 'Python',
        'go': 'Go'
    },

    // Current language state
    currentLanguage: 'java',
    currentView: 'vulnerable', // 'vulnerable' or 'fixed'
    
    // Set language
    setLanguage(lang) {
        this.currentLanguage = lang;
        this.updateCodeDisplay();
        this.updateLanguageTabs();
    },
    
    // Set view mode
    setViewMode(mode) {
        this.currentView = mode;
        this.updateCodeDisplay();
        this.updateViewTabs();
    },
    
    // Update code display (to be implemented by each page)
    updateCodeDisplay() {
        console.warn('updateCodeDisplay not implemented');
    },
    
    // Update language tabs
    updateLanguageTabs() {
        document.querySelectorAll('.lang-tab').forEach(tab => {
            tab.classList.remove('active', 'text-blue-400', 'border-blue-400');
            tab.classList.add('text-gray-500', 'border-transparent');
            if (tab.dataset.lang === this.currentLanguage) {
                tab.classList.add('active', 'text-blue-400', 'border-blue-400');
                tab.classList.remove('text-gray-500', 'border-transparent');
            }
        });
    },
    
    // Update view tabs
    updateViewTabs() {
        document.querySelectorAll('.view-tab').forEach(tab => {
            tab.classList.remove('active', 'bg-blue-600', 'text-white');
            tab.classList.add('bg-gray-700', 'text-gray-300');
            if (tab.dataset.view === this.currentView) {
                tab.classList.add('active', 'bg-blue-600', 'text-white');
                tab.classList.remove('bg-gray-700', 'text-gray-300');
            }
        });
    },

    // Simulate attack result
    simulateAttack(attackInput, vulnerabilityType) {
        const results = {
            'sqli': {
                'admin\' OR \'1\'=\'1\' --': { success: true, message: 'SQL注入成功！使用 OR 1=1 恒真条件绕过了密码验证', data: '用户列表: admin, user1, user2' },
                'admin': { success: false, message: '普通登录失败，请检查用户名密码', data: null },
                'default': { success: false, message: '请尝试使用 SQL注入 payload', data: null }
            },
            'xss': {
                '<script>alert(\'XSS\')</script>': { success: true, message: 'XSS攻击成功！恶意脚本已被执行', data: 'Cookie: session=stolen_by_xss' },
                '<img src=x onerror=alert(1)>': { success: true, message: 'XSS攻击成功！使用img标签触发onerror', data: 'Cookie: session=stolen_by_xss' },
                'default': { success: false, message: '未检测到XSS攻击，请输入XSS payload', data: null }
            },
            'command-injection': {
                '8.8.8.8; cat /etc/passwd': { success: true, message: '命令注入成功！成功读取/etc/passwd文件', data: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon...' },
                '8.8.8.8 && ls': { success: true, message: '命令注入成功！执行了ls命令', data: 'file1.txt\nfile2.jpg\nuploads' },
                'default': { success: false, message: '未检测到命令注入，请输入payload', data: null }
            },
            'ssrf': {
                'http://169.254.169.254/latest/meta-data/': { success: true, message: 'SSRF攻击成功！成功访问AWS元数据服务', data: 'ami-id: ami-12345678\ninstance-type: t2.micro' },
                'http://localhost:6379/': { success: true, message: 'SSRF攻击成功！访问了内网Redis服务', data: 'NOAUTH Authentication required.' },
                'default': { success: false, message: '请输入SSRF payload（如内网地址）', data: null }
            },
            'file-upload': {
                'shell.php': { success: true, message: '文件上传成功！上传了PHP webshell', data: '文件路径: uploads/shell.php' },
                'evil.jpg': { success: false, message: '文件类型不允许，但绕过了前端检测', data: 'Content-Type: image/jpeg 被识别为图片' },
                'default': { success: false, message: '请输入文件名测试文件上传漏洞', data: null }
            },
            'csrf': {
                'csrf_token=abc123': { success: true, message: 'CSRF攻击成功！绕过Token验证', data: '转账完成: $10000 -> attacker' },
                'default': { success: false, message: '缺少CSRF Token验证', data: null }
            },
            'auth-bypass': {
                'session=admin_session': { success: true, message: '会话劫持成功！使用预测的Session ID', data: 'Logged in as: admin' },
                'default': { success: false, message: '请输入Session ID测试认证绕过', data: null }
            },
            'xxe': {
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><name>&xxe;</name></user>': { success: true, message: 'XXE攻击成功！外部实体被解析', data: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon...' },
                'default': { success: false, message: '请输入XXE payload测试XML外部实体注入', data: null }
            }
        };
        
        const vulnResults = results[vulnerabilityType] || results['sqli'];
        return vulnResults[attackInput] || vulnResults['default'];
    }
};

// Export for use
window.VulnerabilityUtils = VulnerabilityUtils;
