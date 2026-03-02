# main.py - Gemini 多模态增强版
from fastapi import FastAPI, HTTPException, Request, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl, validator
import requests
from bs4 import BeautifulSoup
import json
import re
import os
import random
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Union
import urllib3
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from starlette.middleware.base import BaseHTTPMiddleware
import hashlib
import asyncio
from dataclasses import dataclass
from enum import Enum
import google.generativeai as genai
import tempfile
import base64
import mimetypes
from pathlib import Path

# ==================== 配置和初始化 ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scam_detector.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="慧眼伴老 - AI防诈助手API (Gemini多模态版)",
    description="基于端云协同三级判别架构与Google Gemini多模态AI的老年人数字安全防护系统",
    version="4.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


# ==================== 数据模型定义 ====================
class RiskLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class OperationType(str, Enum):
    SHARE = "share"
    PAYMENT = "payment"
    NAVIGATION = "navigation"
    INSTALLATION = "installation"
    UPLOAD = "upload"


class URLRequest(BaseModel):
    url: HttpUrl
    user_id: str = "default_user"
    analysis_type: str = "detailed"
    operation_type: OperationType = OperationType.SHARE
    session_token: Optional[str] = None
    user_context: Optional[str] = None  # 用户提供的额外上下文

    @validator('user_id')
    def validate_user_id(cls, v):
        if not v or v.strip() == "":
            raise ValueError("用户ID不能为空")
        return v


class MediaUploadRequest(BaseModel):
    """用于直接上传文件进行分析的请求模型"""
    file_data: Union[str, bytes]  # base64字符串或字节
    filename: str
    mime_type: str
    user_id: str = "default_user"
    analysis_type: str = "detailed"
    operation_type: OperationType = OperationType.UPLOAD
    user_context: Optional[str] = None


class ScamResponse(BaseModel):
    is_scam: bool
    reason: str
    confidence: float
    title: str
    risk_level: RiskLevel
    success: bool
    analysis_type: str
    processed_content_length: int
    detected_keywords: List[str] = []
    timestamp: str
    recommended_action: Optional[str] = None
    family_notified: bool = False
    confirmation_delay: Optional[int] = None
    scam_category: Optional[str] = None
    media_type: Optional[str] = None


class FamilyAlertRequest(BaseModel):
    user_id: str
    risk_event: Dict[str, Any]
    contact_method: str = "app"


class ComplianceCheckResult(BaseModel):
    authorized: bool
    reason: Optional[str] = None
    user_consent: bool = False
    family_binding_active: bool = False


# ==================== Gemini 多模态分析器 ====================
class GeminiMultimodalAnalyzer:
    """Google Gemini 1.5 多模态分析器"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API密钥未提供。请设置环境变量 GEMINI_API_KEY")

        genai.configure(api_key=self.api_key)
        self.model_name = "models/gemini-1.5-flash"
        self.model = genai.GenerativeModel(self.model_name)
        self.http_client = requests.Session()
        logger.info(f"Gemini多模态分析器初始化完成，使用模型: {self.model_name}")

    async def analyze_content(self, url: str, analysis_type: str = "detailed",
                              user_context: Optional[str] = None) -> Dict[str, Any]:
        """分析URL内容"""
        try:
            logger.info(f"开始多模态分析: {url}, 模式: {analysis_type}")

            # 获取内容
            content_info = await self._fetch_content(url)
            if not content_info:
                return self._create_fallback_result("无法获取或识别该URL的内容。")

            # 构建提示词
            system_prompt = self._build_system_prompt(analysis_type, user_context)

            # 准备Gemini输入
            gemini_input = [system_prompt]

            if content_info["type"] == "text":
                gemini_input.append(content_info["content"])
            else:  # media file
                media_file = genai.upload_file(content_info["path"], mime_type=content_info["mime_type"])
                gemini_input.append(media_file)

            # 调用Gemini API
            response = await self.model.generate_content_async(gemini_input)

            # 解析响应
            result = self._parse_gemini_response(response.text)
            logger.info(f"Gemini分析成功，风险等级: {result.get('risk_level', 'UNKNOWN')}")

            # 清理临时文件
            if content_info["type"] == "media" and os.path.exists(content_info["path"]):
                try:
                    os.unlink(content_info["path"])
                except:
                    pass

            return result

        except Exception as e:
            logger.error(f"Gemini多模态分析过程异常: {e}", exc_info=True)
            return self._create_fallback_result(f"分析服务暂时不可用: {str(e)[:100]}")

    async def analyze_media_file(self, file_path: str, mime_type: str,
                                 analysis_type: str = "detailed",
                                 user_context: Optional[str] = None) -> Dict[str, Any]:
        """分析本地媒体文件"""
        try:
            if not os.path.exists(file_path):
                return self._create_fallback_result("文件不存在")

            # 构建提示词
            system_prompt = self._build_system_prompt(analysis_type, user_context)

            # 上传文件到Gemini
            media_file = genai.upload_file(file_path, mime_type=mime_type)

            # 调用Gemini API
            response = await self.model.generate_content_async([system_prompt, media_file])

            # 解析响应
            result = self._parse_gemini_response(response.text)
            return result

        except Exception as e:
            logger.error(f"Gemini媒体文件分析异常: {e}", exc_info=True)
            return self._create_fallback_result(f"媒体文件分析失败: {str(e)[:100]}")

    async def _fetch_content(self, url: str) -> Optional[Dict[str, Any]]:
        """获取URL内容"""
        try:
            # 检查是否是直接媒体文件
            parsed_url = str(url).lower()
            media_extensions = {
                '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
                '.gif': 'image/gif', '.webp': 'image/webp',
                '.mp4': 'video/mp4', '.mov': 'video/quicktime',
                '.mp3': 'audio/mpeg', '.wav': 'audio/wav'
            }

            for ext, mime_type in media_extensions.items():
                if parsed_url.endswith(ext):
                    # 下载媒体文件
                    response = self.http_client.get(url, timeout=30, stream=True)
                    response.raise_for_status()

                    # 保存到临时文件
                    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                        temp_path = f.name

                    return {
                        "type": "media",
                        "path": temp_path,
                        "mime_type": mime_type,
                        "source": "direct_media"
                    }

            # 否则作为网页处理
            response = self.http_client.get(url, timeout=15,
                                            headers={'User-Agent': 'Mozilla/5.0'})
            response.raise_for_status()

            if 'text/html' in response.headers.get('content-type', '').lower():
                soup = BeautifulSoup(response.text, 'html.parser')
                for script in soup(["script", "style", "nav", "footer", "header"]):
                    script.decompose()

                text = soup.get_text(separator=' ', strip=True)
                title = soup.title.string if soup.title else "无标题"

                return {
                    "type": "text",
                    "content": f"标题: {title}\n\n内容: {text[:15000]}",
                    "title": title,
                    "source": "webpage"
                }

            return None

        except Exception as e:
            logger.error(f"获取内容失败 {url}: {e}")
            return None

    def _build_system_prompt(self, analysis_type: str, user_context: Optional[str]) -> str:
        """构建系统提示词"""
        base_prompt = """你是一位专为老年人设计的"AI防诈骗安全助手"。你的任务是分析用户提供的内容（可能是网页文本、图片、视频或音频），判断其是否存在诈骗风险，并以指定的JSON格式输出分析结果。

请重点关注以下诈骗特征：
1. 财产诈骗：承诺"高收益、零风险、稳赚不赔"、诱导投资、刷单、冒充客服退款、虚假中奖。
2. 身份冒充：冒充"公检法、银行、社保局、疾控中心"等权威机构，制造恐慌，要求转账或提供验证码。
3. 情感诈骗：伪装身份建立亲密关系后索要钱财。
4. 健康误导：夸大保健品疗效、售卖"伪科学"治疗仪、传播未经证实的恐慌性健康信息。
5. 信息窃取：诱导点击不明链接、下载恶意APP、填写个人敏感信息。
6. 伪造证据：图片或视频中出现的伪造的"警官证"、"逮捕令"、"法院传票"、"转账记录"、"聊天记录"。

输出要求：你必须且只能输出一个JSON对象，包含以下字段：
- is_scam (boolean): true 或 false
- reason (string): 详细、可读的解释，用老年人及其子女能理解的语言
- confidence (float): 判断置信度，0.0到1.0之间
- risk_level (string): 只能是 HIGH、MEDIUM、LOW 中的一个
- detected_keywords (list of string): 识别出的与诈骗相关的关键词
- scam_category (string, 可选): 诈骗类型，如"投资理财诈骗"、"冒充公检法"等"""

        if analysis_type == "quick":
            base_prompt += "\n\n模式：快速分析。请重点关注最明显、最直接的风险信号。"
        elif analysis_type == "deep":
            base_prompt += "\n\n模式：深度分析。请仔细审视内容的每一个细节，进行多维度推理。"

        if user_context:
            base_prompt += f"\n\n用户背景信息：{user_context}"

        return base_prompt

    def _parse_gemini_response(self, gemini_output: str) -> Dict[str, Any]:
        """解析Gemini响应"""
        import re

        try:
            json_match = re.search(r'\{.*\}', gemini_output, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group().strip())
                required_fields = ['is_scam', 'reason', 'confidence', 'risk_level']
                if all(field in result for field in required_fields):
                    if 'risk_level' in result:
                        result['risk_level'] = str(result['risk_level']).upper()
                    return result
        except:
            pass

        logger.warning(f"无法从Gemini响应中解析标准JSON: {gemini_output[:200]}...")
        return self._create_fallback_result(gemini_output)

    def _create_fallback_result(self, reason: str) -> Dict[str, Any]:
        """创建降级结果"""
        return {
            "is_scam": False,
            "reason": f"分析引擎响应异常：{reason}",
            "confidence": 0.1,
            "risk_level": "LOW",
            "detected_keywords": ["分析服务降级"],
            "scam_category": "未知"
        }


# ==================== 合规网关实现 ====================
class ComplianceGateway:
    """合规网关 - 架构图第一阶段核心组件"""

    def __init__(self):
        self.user_consent_db = {
            "default_user": True,
            "test_user": True,
            "elderly_user_001": True
        }

        self.family_bindings = {
            "elderly_user_001": {
                "guardian_id": "family_member_001",
                "active": True,
                "risk_threshold": RiskLevel.MEDIUM,
                "created_at": datetime.now() - timedelta(days=30)
            }
        }

        self.rate_limits = {}

    async def validate_operation(self, user_id: str, operation_type: OperationType) -> ComplianceCheckResult:
        """验证操作合规性"""
        user_consent = self.user_consent_db.get(user_id, False)
        if not user_consent:
            return ComplianceCheckResult(
                authorized=False,
                reason="用户未授权使用此服务",
                user_consent=False
            )

        if not await self._check_rate_limit(user_id):
            return ComplianceCheckResult(
                authorized=False,
                reason="操作过于频繁，请稍后重试",
                user_consent=True
            )

        family_binding = self.family_bindings.get(user_id)
        family_active = family_binding and family_binding["active"] if family_binding else False

        logger.info(f"合规检查通过: user_id={user_id}, operation={operation_type}")

        return ComplianceCheckResult(
            authorized=True,
            user_consent=True,
            family_binding_active=family_active
        )

    async def _check_rate_limit(self, user_id: str) -> bool:
        """频率限制检查"""
        now = datetime.now()
        if user_id not in self.rate_limits:
            self.rate_limits[user_id] = []

        self.rate_limits[user_id] = [
            ts for ts in self.rate_limits[user_id]
            if now - ts < timedelta(minutes=1)
        ]

        if len(self.rate_limits[user_id]) >= 10:
            return False

        self.rate_limits[user_id].append(now)
        return True


# ==================== 隐私保护实现 ====================
class PrivacyGuardian:
    """隐私哨兵 - 数据最小化采集和脱敏"""

    def __init__(self):
        self.sensitive_patterns = [
            (r'\d{11}', '[手机号已脱敏]'),
            (r'\d{18}|\d{17}[Xx]', '[身份证号已脱敏]'),
            (r'\d{16,19}', '[银行卡号已脱敏]'),
            (r'\d{3}-\d{8}|\d{4}-\d{7}', '[电话已脱敏]'),
            (r'\w+@\w+\.\w+', '[邮箱已脱敏]')
        ]

    def minimize_data_collection(self, content: str) -> str:
        """执行最小必要数据采集原则"""
        if not content:
            return content

        sanitized_content = content
        for pattern, replacement in self.sensitive_patterns:
            sanitized_content = re.sub(pattern, replacement, sanitized_content)

        sanitized_content = re.sub(r'\d{10,}', '[长数字序列已脱敏]', sanitized_content)

        logger.info(f"隐私处理完成: 原始长度={len(content)}, 脱敏后长度={len(sanitized_content)}")
        return sanitized_content

    def generate_content_hash(self, content: str) -> str:
        """生成内容哈希"""
        return hashlib.md5(content.encode()).hexdigest()


# ==================== 家庭协同系统 ====================
class FamilyGuardianSystem:
    """家庭守护协同中心 - 架构图第三阶段核心"""

    def __init__(self):
        self.family_contacts = {
            "elderly_user_001": [
                {"name": "子女张三", "contact": "13800138000", "type": "sms"},
                {"name": "子女李四", "contact": "wechat_123456", "type": "wechat"}
            ]
        }

        self.notification_history = []

    async def notify_family_members(self, user_id: str, risk_event: Dict[str, Any]) -> bool:
        """通知家庭成员高风险事件"""
        try:
            contacts = self.family_contacts.get(user_id, [])
            if not contacts:
                logger.warning(f"用户 {user_id} 未设置紧急联系人")
                return False

            risk_summary = {
                "user_id": user_id,
                "risk_level": risk_event.get("risk_level", "UNKNOWN"),
                "event_type": risk_event.get("operation_type", "unknown"),
                "timestamp": datetime.now().isoformat(),
                "content_preview": risk_event.get("reason", "")[:100] + "...",
                "detected_keywords": risk_event.get("detected_keywords", [])[:3]
            }

            notification_tasks = []
            for contact in contacts:
                task = self.send_encrypted_alert(contact, risk_summary)
                notification_tasks.append(task)

            results = await asyncio.gather(*notification_tasks, return_exceptions=True)
            success_count = sum(1 for r in results if r is True)

            self.notification_history.append({
                "user_id": user_id,
                "timestamp": datetime.now(),
                "risk_level": risk_summary["risk_level"],
                "contacts_notified": len(contacts),
                "success_count": success_count
            })

            logger.info(f"家庭通知完成: 用户={user_id}, 成功通知={success_count}/{len(contacts)}")
            return success_count > 0

        except Exception as e:
            logger.error(f"家庭通知失败: {e}")
            return False

    async def send_encrypted_alert(self, contact: Dict[str, str], summary: Dict[str, Any]) -> bool:
        """发送加密告警"""
        try:
            await asyncio.sleep(0.1)

            message = f"""【慧眼伴老安全提醒】
您的家人可能正在接触高风险信息：
风险等级：{summary['risk_level']}
事件类型：{summary['event_type']}
检测时间：{summary['timestamp']}
建议操作：请及时沟通确认，谨防上当受骗"""

            logger.info(f"发送家庭告警给 {contact['name']}: {message}")
            return True

        except Exception as e:
            logger.error(f"发送告警失败 {contact['name']}: {e}")
            return False


# ==================== 分级响应引擎 ====================
class HierarchicalResponseEngine:
    """分级响应引擎 - 基于风险等级执行不同策略"""

    def __init__(self, family_system: FamilyGuardianSystem):
        self.family_system = family_system

    async def execute_risk_response(self, risk_data: Dict[str, Any], user_id: str,
                                    operation_type: OperationType) -> Dict[str, Any]:
        """基于风险等级执行分级响应"""
        risk_level = risk_data.get("risk_level", RiskLevel.LOW)

        response_strategies = {
            RiskLevel.HIGH: self._high_risk_response,
            RiskLevel.MEDIUM: self._medium_risk_response,
            RiskLevel.LOW: self._low_risk_response
        }

        strategy = response_strategies.get(risk_level, self._low_risk_response)
        return await strategy(risk_data, user_id, operation_type)

    async def _high_risk_response(self, risk_data: Dict[str, Any], user_id: str,
                                  operation_type: OperationType) -> Dict[str, Any]:
        """高风险响应策略"""
        family_notified = await self.family_system.notify_family_members(user_id, {
            **risk_data,
            "operation_type": operation_type.value
        })

        risk_data["recommended_action"] = "立即终止操作并联系家人确认"
        risk_data["family_notified"] = family_notified
        risk_data["confirmation_delay"] = 30

        return risk_data

    async def _medium_risk_response(self, risk_data: Dict[str, Any], user_id: str,
                                    operation_type: OperationType) -> Dict[str, Any]:
        """中风险响应策略"""
        risk_data["recommended_action"] = "建议仔细核实内容真实性后再操作"
        risk_data["confirmation_delay"] = 10
        risk_data["family_notified"] = False

        return risk_data

    async def _low_risk_response(self, risk_data: Dict[str, Any], user_id: str,
                                 operation_type: OperationType) -> Dict[str, Any]:
        """低风险响应策略"""
        risk_data["recommended_action"] = "可正常操作，系统已记录此次访问"
        risk_data["confirmation_delay"] = None
        risk_data["family_notified"] = False

        return risk_data


# ==================== 初始化核心组件 ====================
# 依赖注入实例
compliance_gateway = ComplianceGateway()
privacy_guardian = PrivacyGuardian()
family_system = FamilyGuardianSystem()
response_engine = HierarchicalResponseEngine(family_system)

# 初始化Gemini多模态分析器
gemini_analyzer = None
try:
    gemini_analyzer = GeminiMultimodalAnalyzer(api_key=os.getenv("GEMINI_API_KEY"))
    logger.info("Gemini多模态分析器初始化成功。")
except Exception as e:
    logger.error(f"Gemini多模态分析器初始化失败: {e}")

# ==================== 中间件 ====================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = datetime.now()
        response = await call_next(request)
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"{request.method} {request.url} - {response.status_code} - {duration:.2f}s")
        return response


app.add_middleware(LoggingMiddleware)


# ==================== API路由实现 ====================
@app.post("/api/check-url", response_model=ScamResponse)
async def check_url(request: URLRequest):
    """Gemini多模态URL风险检测接口"""
    logger.info(f"[Gemini]收到检测请求: {request.url} - 用户: {request.user_id}")

    try:
        # 第一阶段：合规检查
        compliance_result = await compliance_gateway.validate_operation(
            request.user_id, request.operation_type
        )
        if not compliance_result.authorized:
            raise HTTPException(status_code=403, detail=compliance_result.reason)

        # 第二阶段：使用Gemini进行多模态风险分析
        if not gemini_analyzer:
            raise HTTPException(status_code=503, detail="多模态分析服务未就绪")

        ai_result = await gemini_analyzer.analyze_content(
            url=str(request.url),
            analysis_type=request.analysis_type,
            user_context=request.user_context
        )

        # 第三阶段：分级响应处理
        enhanced_result = await response_engine.execute_risk_response(
            ai_result, request.user_id, request.operation_type
        )

        # 构建最终响应
        response_data = {
            "is_scam": enhanced_result.get("is_scam", False),
            "reason": enhanced_result.get("reason", "分析失败"),
            "confidence": round(float(enhanced_result.get("confidence", 0.0)), 2),
            "title": f"内容分析 ({str(request.url)[:50]}...)" if len(
                str(request.url)) > 50 else f"内容分析 ({request.url})",
            "risk_level": enhanced_result.get("risk_level", RiskLevel.LOW),
            "success": True,
            "analysis_type": request.analysis_type,
            "processed_content_length": 0,
            "detected_keywords": enhanced_result.get("detected_keywords", []),
            "timestamp": datetime.now().isoformat(),
            "recommended_action": enhanced_result.get("recommended_action"),
            "family_notified": enhanced_result.get("family_notified", False),
            "confirmation_delay": enhanced_result.get("confirmation_delay"),
            "scam_category": enhanced_result.get("scam_category"),
            "media_type": "multimodal"
        }

        logger.info(f"[Gemini]检测完成: 风险={response_data['risk_level']}, 置信度={response_data['confidence']}")
        return ScamResponse(**response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Gemini]检测过程异常: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="服务器内部错误")


@app.post("/api/analyze-media", response_model=ScamResponse)
async def analyze_media_file(
        file: UploadFile = File(...),
        user_id: str = Form("default_user"),
        analysis_type: str = Form("detailed"),
        operation_type: OperationType = Form(OperationType.UPLOAD),
        user_context: Optional[str] = Form(None)
):
    """直接上传媒体文件进行分析"""
    logger.info(f"[Gemini]收到媒体文件分析请求: {file.filename}, 类型={file.content_type}")

    try:
        # 合规检查
        compliance_result = await compliance_gateway.validate_operation(
            user_id, OperationType(operation_type)
        )
        if not compliance_result.authorized:
            raise HTTPException(status_code=403, detail=compliance_result.reason)

        if not gemini_analyzer:
            raise HTTPException(status_code=503, detail="多模态分析服务未就绪")

        # 保存上传的文件到临时文件
        temp_path = None
        try:
            # 读取文件内容
            contents = await file.read()

            # 创建临时文件
            suffix = Path(file.filename).suffix or '.bin'
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp_file:
                tmp_file.write(contents)
                temp_path = tmp_file.name

            # 使用Gemini分析文件
            ai_result = await gemini_analyzer.analyze_media_file(
                file_path=temp_path,
                mime_type=file.content_type or "application/octet-stream",
                analysis_type=analysis_type,
                user_context=user_context
            )

        finally:
            # 清理临时文件
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except:
                    pass

        # 分级响应处理
        enhanced_result = await response_engine.execute_risk_response(
            ai_result, user_id, OperationType(operation_type)
        )

        # 构建响应
        response_data = {
            "is_scam": enhanced_result.get("is_scam", False),
            "reason": enhanced_result.get("reason", "分析失败"),
            "confidence": round(float(enhanced_result.get("confidence", 0.0)), 2),
            "title": f"文件分析: {file.filename}",
            "risk_level": enhanced_result.get("risk_level", RiskLevel.LOW),
            "success": True,
            "analysis_type": analysis_type,
            "processed_content_length": len(contents) if 'contents' in locals() else 0,
            "detected_keywords": enhanced_result.get("detected_keywords", []),
            "timestamp": datetime.now().isoformat(),
            "recommended_action": enhanced_result.get("recommended_action"),
            "family_notified": enhanced_result.get("family_notified", False),
            "confirmation_delay": enhanced_result.get("confirmation_delay"),
            "scam_category": enhanced_result.get("scam_category"),
            "media_type": file.content_type
        }
        return ScamResponse(**response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Gemini]媒体文件分析异常: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="媒体文件分析失败")


@app.get("/health")
async def health_check():
    """健康检查接口"""
    gemini_status = "active" if gemini_analyzer else "inactive"

    return {
        "status": "healthy",
        "version": "4.0.0",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "compliance_gateway": "active",
            "privacy_guardian": "active",
            "family_system": "active",
            "gemini_analyzer": gemini_status
        }
    }


@app.get("/health/gemini")
async def health_check_gemini():
    """Gemini多模态服务健康检查"""
    status = "healthy"
    details = {}

    try:
        if gemini_analyzer and gemini_analyzer.model:
            details["gemini_model"] = gemini_analyzer.model_name
            details["status"] = "available"
        else:
            status = "unavailable"
            details["error"] = "Gemini分析器未初始化"
    except Exception as e:
        status = "unhealthy"
        details["error"] = str(e)

    return {
        "service": "gemini_multimodal",
        "status": status,
        "timestamp": datetime.now().isoformat(),
        "details": details
    }


@app.post("/api/family/alert")
async def send_family_alert(alert_request: FamilyAlertRequest):
    """家庭告警接口"""
    success = await family_system.notify_family_members(
        alert_request.user_id, alert_request.risk_event
    )
    return {"success": success, "alert_sent": success}


@app.get("/api/compliance/status/{user_id}")
async def get_compliance_status(user_id: str):
    """获取用户合规状态"""
    result = await compliance_gateway.validate_operation(user_id, OperationType.SHARE)
    return {
        "user_id": user_id,
        "authorized": result.authorized,
        "user_consent": result.user_consent,
        "family_binding_active": result.family_binding_active,
        "timestamp": datetime.now().isoformat()
    }


# ==================== 错误处理 ====================
@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": str(exc.detail)}
    )


@app.exception_handler(Exception)
async def general_exception_handler(_request: Request, exc: Exception):
    logger.error(f"服务器内部错误: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "服务器内部错误"}
    )


# ==================== 应用生命周期 ====================
@app.on_event("startup")
async def startup_event():
    """应用启动时执行"""
    logger.info("慧眼伴老防诈助手 (Gemini多模态版) v4.0.0 正在启动...")


@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭时执行"""
    logger.info("应用正在关闭...")
    if gemini_analyzer and hasattr(gemini_analyzer, 'http_client'):
        gemini_analyzer.http_client.close()
    logger.info("资源清理完成。")


# ==================== 启动服务 ====================
if __name__ == "__main__":
    import uvicorn

    logger.info("启动慧眼伴老防诈助手服务 v4.0.0...")
    logger.info("架构特性: 合规网关 + 隐私保护 + 家庭协同 + Gemini多模态分析")

    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "8000"))

    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=os.getenv("DEBUG_MODE", "False").lower() == "true"
    )