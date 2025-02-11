import os
import re
import asyncio
from openai import AsyncOpenAI
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import QThread, pyqtSignal

# ================= Utility Functions =================
def split_content(content, chunk_size=5000):
    """
    将日志内容分段
    :param content: 日志内容 (str)
    :param chunk_size: 每段的最大字符数
    :return: 分段后的内容列表
    """
    return [content[i:i + chunk_size] for i in range(0, len(content), chunk_size)]


# ================= AI 分析模块 =================
class AILogAnalyzer:
    def __init__(self, api_key):
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url="https://ark.cn-beijing.volces.com/api/v3"
        )
        self.prompt_template = """作为网络安全专家，分析以下 Windows 日志片段，请：
1. 识别潜在安全风险（高危/中危/低危）
2. 解释风险原因
3. 提供应对建议
4. 用 JSON 格式返回结果，包含字段：risk_level, risk_type, description, recommendation

日志内容：
{log_chunk}"""

    async def analyze(self, log_chunk):
        try:
            completion = await self.client.chat.completions.create(
                model="你模型的号码",
                messages=[
                    {"role": "system", "content": "你是一个专业的网络安全分析助手，擅长从日志中发现安全威胁"},
                    {"role": "user", "content": self.prompt_template.format(log_chunk=log_chunk[:3000])}
                ],
                temperature=0.3,
                max_tokens=500
            )
            return completion.choices[0].message.content if completion.choices else "⚠️ AI 未返回有效响应"
        except Exception as e:
            return f"AI 分析错误: {str(e)}"


# ================= 规则引擎分析工作线程 =================



class RuleEngineWorker(QThread):
    analysis_complete = pyqtSignal(str)
    progress_update = pyqtSignal(int)

    def __init__(self, log_files):
        super().__init__()
        self.log_files = log_files
        self._is_cancelled = False  # 取消标志位
        self.load_rules()

    def cancel(self):
        """设置取消标志位"""
        self._is_cancelled = True

    def load_rules(self):
        """加载规则"""
        self.rules = {
            # ========== Windows 系统日志规则 ==========
            "win_bruteforce": {
                "pattern": r'(Event ID:\s*4625)[\s\S]*?Logon Type:\s*(\d+)[\s\S]*?Account Name:\s*(\S+)[\s\S]*?(Source Network Address:\s*(\S+))?',
                "risk_level": "高危",
                "type": "远程暴力破解尝试"
            },
            "win_account_lockout": {
                "pattern": r'Event ID:\s*4740[\s\S]*?Target Account Name:\s*(\S+)[\s\S]*?Caller Computer Name:\s*(\S+)',
                "risk_level": "中危",
                "type": "账户锁定事件"
            },
            "win_service_stopped": {
                "pattern": r'Event ID:\s*7036[\s\S]*?The (\S+) service entered the stopped state',
                "risk_level": "中危",
                "type": "服务停止事件"
            },
            "win_policy_change": {
                "pattern": r'Event ID:\s*4719[\s\S]*?Account Name:\s*(\S+)[\s\S]*?Policy Change:\s*(\S+)',
                "risk_level": "高危",
                "type": "系统策略更改"
            },

            # ========== Linux 系统日志规则 ==========
            "linux_ssh_login_success": {
                "pattern": r'sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port (\d+)',
                "risk_level": "信息",
                "type": "SSH 登录成功"
            },
            "linux_ssh_login_failure": {
                "pattern": r'sshd\[\d+\]: Failed password for (\S+) from (\S+) port (\d+)',
                "risk_level": "中危",
                "type": "SSH 登录失败"
            },
            "linux_privilege_escalation": {
                "pattern": r'(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)',
                "risk_level": "高危",
                "type": "提权操作检测"
            },
            "linux_file_permission_change": {
                "pattern": r'(\S+ \d+ \S+) chmod\[\d+\]: (.+) changed permissions of file (\S+) to (\S+)',
                "risk_level": "中危",
                "type": "文件权限更改"
            },

            # ========== 网络设备日志规则 ==========
            "network_firewall_change": {
                "pattern": r'Firewall rule (\S+) (added|removed|modified) by (\S+)',
                "risk_level": "高危",
                "type": "防火墙规则变更"
            },
            "network_port_scan": {
                "pattern": r'Scanning detected from (\S+) to (\S+) on ports (\d+)-(\d+)',
                "risk_level": "高危",
                "type": "端口扫描检测"
            },
            "network_traffic_anomaly": {
                "pattern": r'Anomalous traffic detected: (\S+) -> (\S+) with volume (\d+) MB',
                "risk_level": "高危",
                "type": "流量异常检测"
            },

            # ========== Web 应用日志规则 ==========
            "web_sql_injection": {
                "pattern": r'SQL Injection attempt detected: (.+) in parameter (\S+)',
                "risk_level": "高危",
                "type": "SQL 注入攻击"
            },
            "web_file_upload_exploit": {
                "pattern": r'File upload detected: (\S+) uploaded by (\S+) with type (\S+)',
                "risk_level": "高危",
                "type": "文件上传漏洞利用"
            },
            "web_xss_attack": {
                "pattern": r'XSS attempt detected: (.+) in parameter (\S+)',
                "risk_level": "高危",
                "type": "跨站脚本攻击"
            },
            "web_sensitive_file_access": {
                "pattern": r'Sensitive file access detected: (\S+) accessed by (\S+)',
                "risk_level": "中危",
                "type": "敏感文件访问"
            }
        }

    def preprocess_log_content(self, content):
        """对日志内容进行预处理，统一格式"""
        # 替换多余的空白字符
        content = re.sub(r'\s+', ' ', content)
        # 替换换行符
        content = content.replace('\r\n', '\n').replace('\r', '\n')
        # 删除开头和结尾的多余空格
        content = content.strip()
        return content

    def run(self):
        """主运行逻辑"""
        full_report = []
        total_files = len(self.log_files)

        for file_idx, filepath in enumerate(self.log_files):
            if self._is_cancelled:  # 检查是否取消任务
                full_report.append("❌ 分析已被用户取消")
                break

            full_report.append(f"📄 文件: {os.path.basename(filepath)}")
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1_000_000)

                # 预处理日志内容
                content = self.preprocess_log_content(content)

                # 分段处理
                findings = []
                for rule_name, rule in self.rules.items():
                    # 使用跨行匹配
                    matches = re.finditer(rule['pattern'], content, re.DOTALL)
                    for match in matches:
                        # 捕获正则表达式分组内容
                        groups = (str(g) if g is not None else "[未匹配]" for g in match.groups())
                        findings.append(f"🔍【规则-{rule['risk_level']}] {rule['type']}\n{' | '.join(groups)}")

                # 添加到报告
                full_report.append(f"📊 检测到 {len(findings)} 个风险")
                full_report.extend(findings)
                full_report.append("━" * 50)

            except Exception as e:
                full_report.append(f"❌ 文件处理错误: {str(e)}")

            # 更新进度条
            self.progress_update.emit(int((file_idx + 1) / total_files * 100))

        # 分析完成后发射信号
        self.analysis_complete.emit("\n".join(full_report))


# ================= AI 分析工作线程 =================
class AIAnalysisWorker(QThread):
    analysis_complete = pyqtSignal(str)
    progress_update = pyqtSignal(int)

    def __init__(self, log_files, api_key):
        super().__init__()
        self.log_files = log_files
        self.api_key = api_key
        self._is_cancelled = False  # 取消标志位

    def cancel(self):
        """设置取消标志位"""
        self._is_cancelled = True

    async def _async_analyze(self):
        full_report = []
        total_files = len(self.log_files)

        for file_idx, filepath in enumerate(self.log_files):
            if self._is_cancelled:  # 检查是否取消任务
                full_report.append("❌ AI 分析已被用户取消")
                break

            full_report.append(f"📄 文件: {os.path.basename(filepath)}")
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1_000_000)

                # 分段处理
                chunks = split_content(content, chunk_size=3000)
                for chunk_idx, chunk in enumerate(chunks):
                    if self._is_cancelled:  # 检查是否取消任务
                        full_report.append("❌ AI 分析已被用户取消")
                        break

                    analyzer = AILogAnalyzer(self.api_key)
                    ai_result = await analyzer.analyze(chunk)
                    full_report.append(f"🔍 AI 分析结果（分段 {chunk_idx + 1}/{len(chunks)}）:")
                    full_report.append(ai_result)

                    # 更新进度条
                    self.progress_update.emit(int((file_idx + (chunk_idx + 1) / len(chunks)) / total_files * 100))

            except Exception as e:
                full_report.append(f"❌ 文件处理错误: {str(e)}")

        return "\n".join(full_report)

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(self._async_analyze())
        self.analysis_complete.emit(result)


# ================= 界面和主程序逻辑 =================
class LogAnalyzer(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("火山方舟日志分析终端 v3.0")
        self.setGeometry(100, 100, 1280, 720)
        self.setup_ui()
        self.log_files = []  # 存储选中的日志文件路径
        self.rule_thread = None  # 规则引擎线程
        self.ai_thread = None  # AI 分析线程
        self.is_analyzing = False  # 是否正在分析

    def setup_ui(self):
        # 主界面布局
        main_widget = QtWidgets.QWidget()
        self.setCentralWidget(main_widget)
        layout = QtWidgets.QHBoxLayout(main_widget)

        # 左侧操作面板
        left_panel = QtWidgets.QFrame()
        left_panel.setFrameShape(QtWidgets.QFrame.StyledPanel)
        left_layout = QtWidgets.QVBoxLayout(left_panel)

        # API 密钥输入框
        self.api_key_input = QtWidgets.QLineEdit()
        self.api_key_input.setPlaceholderText("输入火山方舟 API 密钥")
        self.api_key_input.textChanged.connect(self.update_buttons_state)
        left_layout.addWidget(self.api_key_input)

        # 文件选择按钮
        self.btn_select = QtWidgets.QPushButton("📁 选择日志文件")
        self.btn_select.clicked.connect(self.select_logs)
        left_layout.addWidget(self.btn_select)

        # 文件列表显示
        self.file_list = QtWidgets.QListWidget()
        left_layout.addWidget(self.file_list)

        # 分析按钮（规则引擎）
        self.btn_rule_engine = QtWidgets.QPushButton("⚙️ 使用规则引擎分析")
        self.btn_rule_engine.clicked.connect(self.start_rule_analysis)
        self.btn_rule_engine.setEnabled(False)  # 初始不可用
        left_layout.addWidget(self.btn_rule_engine)

        # 分析按钮（AI 分析）
        self.btn_ai_analysis = QtWidgets.QPushButton("🧠 使用 AI 分析")
        self.btn_ai_analysis.clicked.connect(self.start_ai_analysis)
        self.btn_ai_analysis.setEnabled(False)  # 初始不可用
        left_layout.addWidget(self.btn_ai_analysis)

        # 取消按钮
        self.btn_cancel = QtWidgets.QPushButton("❌ 取消分析")
        self.btn_cancel.clicked.connect(self.cancel_analysis)
        self.btn_cancel.setEnabled(False)  # 初始不可用
        left_layout.addWidget(self.btn_cancel)

        # 分隔条
        left_layout.addStretch(1)
        layout.addWidget(left_panel, 1)

        # 右侧结果面板
        right_panel = QtWidgets.QFrame()
        right_panel.setFrameShape(QtWidgets.QFrame.StyledPanel)
        right_layout = QtWidgets.QVBoxLayout(right_panel)

        # 进度条
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setAlignment(QtCore.Qt.AlignCenter)
        self.progress_bar.setFormat("等待分析...")
        right_layout.addWidget(self.progress_bar)

        # 分析结果显示
        self.result_display = QtWidgets.QTextEdit()
        self.result_display.setReadOnly(True)
        right_layout.addWidget(self.result_display)

        layout.addWidget(right_panel, 2)

    def select_logs(self):
        """选择日志文件"""
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(
            self, "选择日志文件", "", "日志文件 (*.log *.txt);;所有文件 (*)"
        )
        if files:
            self.log_files = files
            self.file_list.clear()
            self.file_list.addItems(files)
            # 启用分析按钮
            self.update_buttons_state()

    def update_buttons_state(self):
        """根据文件选择和 API 密钥状态更新按钮可用性"""
        has_files = bool(self.log_files)
        has_api_key = bool(self.api_key_input.text().strip())
        self.btn_rule_engine.setEnabled(has_files and not self.is_analyzing)
        self.btn_ai_analysis.setEnabled(has_files and has_api_key and not self.is_analyzing)
        self.btn_cancel.setEnabled(self.is_analyzing)

    def start_rule_analysis(self):
        """启动规则引擎分析"""
        self.is_analyzing = True
        self.update_buttons_state()
        self.progress_bar.setValue(0)
        self.result_display.clear()

        self.rule_thread = RuleEngineWorker(self.log_files)
        self.rule_thread.progress_update.connect(self.update_progress)
        self.rule_thread.analysis_complete.connect(self.show_results)
        self.rule_thread.finished.connect(self.analysis_finished)
        self.rule_thread.start()

    def start_ai_analysis(self):
        """启动 AI 分析"""
        if not self.api_key_input.text().strip():
            QtWidgets.QMessageBox.warning(self, "警告", "请先输入 API 密钥！")
            return

        self.is_analyzing = True
        self.update_buttons_state()
        self.progress_bar.setValue(0)
        self.result_display.clear()

        self.ai_thread = AIAnalysisWorker(self.log_files, self.api_key_input.text().strip())
        self.ai_thread.progress_update.connect(self.update_progress)
        self.ai_thread.analysis_complete.connect(self.show_results)
        self.ai_thread.finished.connect(self.analysis_finished)
        self.ai_thread.start()

    def update_progress(self, value):
        """更新进度条"""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(f"分析进度: {value}%")

    def show_results(self, result):
        """显示分析结果"""
        self.result_display.setPlainText(result)

    def analysis_finished(self):
        """分析完成"""
        self.is_analyzing = False
        self.update_buttons_state()
        self.progress_bar.setFormat("分析完成！")

    def cancel_analysis(self):
        """取消当前分析任务"""
        if self.rule_thread and self.rule_thread.isRunning():
            self.rule_thread.cancel()
        if self.ai_thread and self.ai_thread.isRunning():
            self.ai_thread.cancel()
        self.is_analyzing = False
        self.update_buttons_state()
        self.result_display.append("⚠️ 分析已被取消！")


# ================= 主程序入口 =================
if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = LogAnalyzer()
    window.show()
    sys.exit(app.exec_())
