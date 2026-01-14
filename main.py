# 导入必要的库
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
import requests
from bs4 import BeautifulSoup
import json
import re
import os
import random
import logging
from datetime import datetime
from typing import Optional, List
import urllib3
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from starlette.middleware.base import BaseHTTPMiddleware

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scam_detector.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# 创建FastAPI应用实例
app = FastAPI(
    title="老年AI防诈助手API",
    description="专门为老年人设计的诈骗检测服务",
    version="2.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 生产环境应该限制具体域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 定义数据模型
class URLRequest(BaseModel):
    url: HttpUrl
    user_id: Optional[str] = "default_user"
    analysis_type: Optional[str] = "detailed"  # quick, detailed, deep


class ScamResponse(BaseModel):
    is_scam: bool
    reason: str
    confidence: float
    title: str
    risk_level: str
    success: bool
    analysis_type: str
    processed_content_length: int
    detected_keywords: Optional[List[str]] = []
    timestamp: str


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    active_workers: int


# 全局配置
MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", "5000"))
CACHE_DURATION = int(os.getenv("CACHE_DURATION", "300"))  # 5分钟缓存


# 创建带重试机制的会话
def create_session_with_retries():
    """创建带重试机制的会话"""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# 轮换的User-Agent列表
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
]

# 网页内容缓存字典
_content_cache = {}
_cache_timestamps = {}


def get_cached_content(url: str) -> tuple:
    """
    带缓存的网页内容获取
    """
    now = datetime.now()

    # 检查缓存是否有效
    if url in _content_cache:
        cache_time = _cache_timestamps.get(url)
        if cache_time and (now - cache_time).seconds < CACHE_DURATION:
            logger.info(f"从缓存获取内容: {url}")
            return _content_cache[url]

    # 缓存过期或不存在，重新抓取
    content = get_webpage_content_enhanced(url)
    if content != (None, None):
        _content_cache[url] = content
        _cache_timestamps[url] = now
    return content


def get_webpage_content_enhanced(url: str) -> tuple:
    """
    增强版网页抓取函数，具有更好的反爬虫能力
    """
    try:
        logger.info(f"开始抓取网页: {url}")

        # 随机选择User-Agent
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Referer': 'https://www.google.com/',
            'DNT': '1'
        }

        session = create_session_with_retries()
        response = session.get(str(url), headers=headers, timeout=15)
        response.raise_for_status()

        # 检测内容类型
        content_type = response.headers.get('content-type', '')
        if 'text/html' not in content_type:
            logger.warning(f"非HTML内容类型: {content_type}")
            return None, None

        soup = BeautifulSoup(response.content, 'html.parser')

        # 获取网页标题
        title = soup.title.string if soup.title else "无标题"

        # 移除不需要的标签
        for script in soup(["script", "style", "nav", "footer", "header", "aside", "meta", "link"]):
            script.decompose()

        # 优先获取主要内容区域
        main_content = None
        for selector in ['main', 'article', '.content', '#content', 'div[role="main"]']:
            if selector.startswith('.') or selector.startswith('#'):
                main_content = soup.select_one(selector)
            else:
                main_content = soup.find(selector)
            if main_content:
                break

        if main_content:
            text = main_content.get_text()
        else:
            text = soup.get_text()

        # 清理文本
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        clean_text = ' '.join(chunk for chunk in chunks if chunk)

        # 限制文本长度
        truncated_text = clean_text[:MAX_CONTENT_LENGTH] if len(clean_text) > MAX_CONTENT_LENGTH else clean_text

        logger.info(f"成功抓取网页: 标题='{title}', 内容长度={len(truncated_text)}")
        return title, truncated_text

    except requests.exceptions.RequestException as e:
        logger.error(f"网络请求失败: {e}")
        return None, None
    except Exception as e:
        logger.error(f"解析网页失败: {e}")
        return None, None


def extract_json_from_text(text: str) -> Optional[dict]:
    """
    从文本中提取JSON内容
    """
    try:
        # 尝试多种JSON模式匹配
        patterns = [
            r'\{[^{}]*\{[^{}]*\}[^{}]*\}',  # 嵌套对象
            r'\{.*\}',  # 简单对象
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                json_str = match.group()
                # 清理可能的Markdown代码块标记
                json_str = re.sub(r'```json|```', '', json_str).strip()
                return json.loads(json_str)

        # 如果无法提取，尝试直接解析整个文本
        return json.loads(text.strip())
    except Exception as e:
        logger.warning(f"JSON提取失败: {e}")
        return None


def analyze_with_ai_enhanced(content: str, title: str, analysis_type: str = "detailed") -> dict:
    """
    增强版AI分析函数，支持多种分析模式
    """
    api_key = os.getenv("QWEN_API_KEY")

    if not api_key:
        logger.warning("未设置QWEN_API_KEY，使用规则分析")
        return fallback_analysis_enhanced(content, title)

    # 根据分析类型调整提示词
    prompt_templates = {
        "quick": """快速分析网页风险：
标题：{title}
内容：{content}

请用一句话判断是否为诈骗，返回JSON：{{"is_scam":布尔值,"reason":"简短原因","confidence":0.0-1.0,"risk_level":"HIGH/MEDIUM/LOW"}}""",

        "deep": """深度分析网页诈骗风险：
标题：{title}
内容：{content}

请详细分析以下维度：
1. 内容真实性 2. 诱导行为 3. 权威性 4. 紧急程度 5. 信息收集
返回完整JSON分析报告：{{"is_scam":布尔值,"reason":"详细分析","confidence":0.0-1.0,"risk_level":"HIGH/MEDIUM/LOW","details":{{"authenticity":评分,"urgency":评分,"authority":评分}}}}""",

        "detailed": """分析网页诈骗风险：
标题：{title}
内容：{content}

检查特征：高收益承诺、敏感信息收集、权威机构冒充、紧急威胁语言、可疑网址。
返回JSON：{{"is_scam":布尔值,"reason":"分析理由","confidence":0.0-1.0,"risk_level":"HIGH/MEDIUM/LOW"}}"""
    }

    prompt_template = prompt_templates.get(analysis_type, prompt_templates["detailed"])
    prompt = prompt_template.format(title=title, content=content[:3000])  # 限制内容长度

    try:
        logger.info(f"调用AI分析，模式: {analysis_type}")

        response = requests.post(
            "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "qwen-plus",
                "input": {
                    "messages": [
                        {
                            "role": "system",
                            "content": "你是专业的反诈骗AI助手，用中文回复，严格返回JSON格式。"
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                },
                "parameters": {
                    "result_format": "message",
                    "temperature": 0.1
                }
            },
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            ai_output = result["output"]["choices"][0]["message"]["content"]
            logger.info(f"AI分析完成: {ai_output[:100]}...")

            ai_result = extract_json_from_text(ai_output)
            if ai_result:
                return ai_result
            else:
                logger.warning("AI返回格式异常，使用备用分析")
                return fallback_analysis_enhanced(content, title)
        else:
            logger.error(f"API调用失败: {response.status_code}")
            return fallback_analysis_enhanced(content, title)

    except Exception as e:
        logger.error(f"AI分析异常: {e}")
        return fallback_analysis_enhanced(content, title)


def fallback_analysis_enhanced(content: str, title: str) -> dict:
    """
    增强版备用分析方案
    """
    scam_keywords = [
        # 扩展关键词库
        "高收益", "零风险", "稳赚不赔", "保本保息", "日赚千元", "投资回报", "暴利项目",
        "内部消息", "涨停板", "公安局", "检察院", "法院", "通缉令", "刑事拘留", "涉嫌违法",
        "洗钱犯罪", "安全账户", "资金清查", "立即处理", "最后机会", "过期作废", "账户冻结",
        "信用受损", "影响子女", "法律后果", "验证码", "银行卡号", "身份证号", "密码确认",
        "个人信息", "账户安全", "幸运用户", "中奖通知", "领奖手续", "公证费用", "所得税",
        "奖金发放", "点击领取", "限时优惠", "独家机会", "稳赚", "高回报", "低投入"
    ]

    combined_text = f"{title} {content}".lower()
    detected_keywords = [kw for kw in scam_keywords if kw in combined_text]
    scam_count = len(detected_keywords)

    # 基于关键词数量和内容特征计算风险
    risk_score = min(scam_count * 0.2, 0.8)  # 基础分数

    # 增加紧急词汇检测
    urgency_words = ["立即", "马上", "赶紧", "最后", "限时", "过期"]
    urgency_count = sum(1 for word in urgency_words if word in combined_text)
    risk_score += urgency_count * 0.1

    # 确定风险等级
    if risk_score >= 0.6:
        risk_level = "HIGH"
        is_scam = True
    elif risk_score >= 0.3:
        risk_level = "MEDIUM"
        is_scam = True
    else:
        risk_level = "LOW"
        is_scam = False

    confidence = min(0.3 + risk_score, 0.95)

    reason = "规则分析: "
    if detected_keywords:
        reason += f"检测到风险关键词: {', '.join(detected_keywords[:5])}"
    else:
        reason += "未发现明显风险特征"

    return {
        "is_scam": is_scam,
        "reason": reason,
        "confidence": confidence,
        "risk_level": risk_level,
        "detected_keywords": detected_keywords
    }


# 中间件：记录请求日志
class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = datetime.now()
        response = await call_next(request)
        duration = (datetime.now() - start_time).total_seconds()

        logger.info(f"{request.method} {request.url} - {response.status_code} - {duration:.2f}s")
        return response


app.add_middleware(LoggingMiddleware)


# API接口
@app.post("/api/check-url", response_model=ScamResponse)
async def check_url(request: URLRequest):
    """
    主要的URL检测接口
    """
    logger.info(f"收到检测请求: {request.url} - 用户: {request.user_id} - 模式: {request.analysis_type}")

    try:
        # 获取网页内容（使用缓存）
        title, content = get_cached_content(str(request.url))

        if not content:
            raise HTTPException(status_code=400, detail="无法访问该网页，请检查URL是否正确或稍后重试")

        # 使用AI进行分析
        result = analyze_with_ai_enhanced(content, title, request.analysis_type)

        # 构建响应
        response_data = {
            "is_scam": result.get("is_scam", False),
            "reason": result.get("reason", "分析失败"),
            "confidence": round(result.get("confidence", 0.0), 2),
            "title": title or "未知标题",
            "risk_level": result.get("risk_level", "UNKNOWN"),
            "success": True,
            "analysis_type": request.analysis_type,
            "processed_content_length": len(content) if content else 0,
            "detected_keywords": result.get("detected_keywords", []),
            "timestamp": datetime.now().isoformat()
        }

        logger.info(
            f"检测完成: 诈骗={response_data['is_scam']} 置信度={response_data['confidence']} 风险={response_data['risk_level']}")
        return ScamResponse(**response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"检测过程异常: {e}")
        raise HTTPException(status_code=500, detail="服务器内部错误，请稍后重试")


@app.get("/", response_model=HealthResponse)
async def root():
    """根路径，返回服务状态"""
    return HealthResponse(
        status="服务正常运行",
        version="2.1.0",
        timestamp=datetime.now().isoformat(),
        active_workers=1
    )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """健康检查接口"""
    return HealthResponse(
        status="healthy",
        version="2.1.0",
        timestamp=datetime.now().isoformat(),
        active_workers=1
    )


@app.get("/api/status")
async def api_status():
    """API状态检查"""
    return {
        "service": "老年AI防诈助手",
        "status": "operational",
        "version": "2.1.0",
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "check_url": "POST /api/check-url",
            "health": "GET /health",
            "docs": "GET /docs"
        }
    }


# 错误处理
@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException):
    logger.warning(f"HTTP异常: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": str(exc.detail)}
    )


@app.exception_handler(Exception)
async def general_exception_handler(_request: Request, exc: Exception):
    logger.error(f"服务器内部错误: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "服务器内部错误，请稍后重试"}
    )


# 启动服务
if __name__ == "__main__":
    import uvicorn

    logger.info("启动老年AI防诈助手服务 v2.1.0...")

    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "8000"))

    logger.info(f"服务地址: http://{host}:{port}")
    logger.info(f"API文档: http://{host}:{port}/docs")

    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=os.getenv("DEBUG_MODE", "False").lower() == "true"
    )