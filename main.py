# 导入必要的库
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
from bs4 import BeautifulSoup
import json
import re
import os
from typing import Optional

# 创建FastAPI应用实例
app = FastAPI(
    title="老年AI防诈助手API",
    description="专门为老年人设计的诈骗检测服务",
    version="1.0.0"
)

# 添加CORS中间件（允许前端应用调用）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 生产环境应该限制具体域名
    allow_credentials=True,
    allow_methods=["*"],  # 允许所有HTTP方法
    allow_headers=["*"],  # 允许所有HTTP头
)


# 定义请求数据模型
class URLRequest(BaseModel):
    url: str
    user_id: Optional[str] = "default_user"


# 定义响应数据模型
class ScamResponse(BaseModel):
    is_scam: bool
    reason: str
    confidence: float
    title: str
    risk_level: str
    success: bool


def get_webpage_content(url: str) -> tuple:
    """
    获取网页内容的详细函数
    参数: url - 要检测的网页地址
    返回: (标题, 内容) 元组
    """
    try:
        print(f"正在抓取网页: {url}")

        # 设置请求头，模拟浏览器访问
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive'
        }

        # 发送HTTP请求，设置超时时间
        response = requests.get(url, headers=headers, timeout=10)

        # 检查请求是否成功
        response.raise_for_status()

        # 使用BeautifulSoup解析HTML
        soup = BeautifulSoup(response.content, 'html.parser')

        # 获取网页标题
        title = soup.title.string if soup.title else "无标题"
        print(f"网页标题: {title}")

        # 移除不需要的标签（脚本、样式等）
        for script in soup(["script", "style", "nav", "footer", "header"]):
            script.decompose()

        # 获取纯文本内容
        text = soup.get_text()

        # 清理文本：移除多余的空行和空格
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        clean_text = ' '.join(chunk for chunk in chunks if chunk)

        # 限制文本长度，避免处理过长的内容
        truncated_text = clean_text[:2000]
        print(f"获取到文本长度: {len(truncated_text)} 字符")

        return title, truncated_text

    except requests.exceptions.RequestException as e:
        print(f"网络请求失败: {e}")
        return None, None
    except Exception as e:
        print(f"解析网页失败: {e}")
        return None, None


def analyze_with_ai(content: str, title: str) -> dict:
    """
    使用AI分析网页内容的详细函数
    参数: content - 网页内容, title - 网页标题
    返回: 分析结果字典
    """
    # 方法1: 使用通义千问API（效果最好）
    api_key = os.getenv("QWEN_API_KEY")

    if api_key:
        print("使用通义千问API进行分析...")

        # 构造详细的提示词
        prompt = f"""
        你是一个专业的反诈骗AI助手，专门帮助老年人识别网络诈骗。

        请分析以下网页内容，判断它是否是诈骗网站：

        网页标题: {title}
        网页内容: {content}

        请重点检查以下特征：
        1. 是否承诺高收益、零风险的投资回报
        2. 是否要求提供银行卡号、密码、验证码等敏感信息
        3. 是否冒充公检法、银行、政府机关等权威机构
        4. 是否使用紧急、威胁性语言制造恐慌
        5. 是否要求立即转账或支付保证金
        6. 网址是否可疑（非正规域名）

        请按照以下JSON格式返回分析结果：
        {{
            "is_scam": true或false,
            "reason": "详细的分析理由，用中文描述",
            "confidence": 0.0到1.0之间的置信度,
            "risk_level": "HIGH/MEDIUM/LOW"
        }}

        请确保返回的内容是纯JSON格式，不要包含其他文字。
        """

        try:
            # 调用通义千问API
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
                                "content": "你是一个专业的反诈骗专家，专门帮助老年人识别网络诈骗。请用中文回复。"
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ]
                    },
                    "parameters": {
                        "result_format": "message",
                        "temperature": 0.1  # 降低随机性，使结果更稳定
                    }
                },
                timeout=30  # 设置较长的超时时间
            )

            if response.status_code == 200:
                result = response.json()
                ai_output = result["output"]["choices"][0]["message"]["content"]
                print(f"AI原始返回: {ai_output}")

                # 使用正则表达式提取JSON部分
                json_match = re.search(r'\{.*\}', ai_output, re.DOTALL)
                if json_match:
                    ai_result = json.loads(json_match.group())
                    print("成功解析AI返回结果")
                    return ai_result
                else:
                    print("无法从AI返回中提取JSON，使用备用方案")
                    return fallback_analysis(content, title)

            else:
                print(f"API调用失败，状态码: {response.status_code}")
                return fallback_analysis(content, title)

        except Exception as e:
            print(f"AI分析过程中出错: {e}")
            return fallback_analysis(content, title)

    else:
        print("未设置API密钥，使用备用规则分析")
        return fallback_analysis(content, title)


def fallback_analysis(content: str, title: str) -> dict:
    """
    备用分析方案：基于规则的简单判断
    当AI服务不可用时使用
    """
    print("使用备用规则进行分析...")

    # 定义诈骗关键词库
    scam_keywords = [
        # 金融诈骗类
        "高收益", "零风险", "稳赚不赔", "保本保息", "日赚千元",
        "投资回报", "暴利项目", "内部消息", "涨停板",

        # 冒充公检法类
        "公安局", "检察院", "法院", "通缉令", "刑事拘留",
        "涉嫌违法", "洗钱犯罪", "安全账户", "资金清查",

        # 威胁紧急类
        "立即处理", "最后机会", "过期作废", "账户冻结",
        "信用受损", "影响子女", "法律后果",

        # 个人信息类
        "验证码", "银行卡号", "身份证号", "密码确认",
        "个人信息", "账户安全",

        # 中奖诈骗类
        "幸运用户", "中奖通知", "领奖手续", "公证费用",
        "所得税", "奖金发放"
    ]

    # 统计关键词出现次数
    scam_count = 0
    detected_keywords = []

    combined_text = f"{title} {content}"

    for keyword in scam_keywords:
        if keyword in combined_text:
            scam_count += 1
            detected_keywords.append(keyword)

    print(f"检测到 {scam_count} 个风险关键词: {detected_keywords}")

    # 根据关键词数量判断风险等级
    if scam_count >= 3:
        risk_level = "HIGH"
        is_scam = True
        confidence = min(0.3 + scam_count * 0.2, 0.95)
        reason = f"检测到多个高风险关键词: {', '.join(detected_keywords[:3])}"
    elif scam_count >= 1:
        risk_level = "MEDIUM"
        is_scam = True
        confidence = 0.5 + scam_count * 0.1
        reason = f"检测到可疑关键词: {', '.join(detected_keywords[:2])}"
    else:
        risk_level = "LOW"
        is_scam = False
        confidence = 0.8
        reason = "未发现明显的诈骗特征"

    return {
        "is_scam": is_scam,
        "reason": reason,
        "confidence": confidence,
        "risk_level": risk_level
    }


# 定义API接口
@app.post("/api/check-url", response_model=ScamResponse)
async def check_url(request: URLRequest):
    """
    主要的URL检测接口
    接收URL，返回诈骗检测结果
    """
    print(f"收到检测请求: {request.url}")

    # 验证URL格式
    if not request.url.startswith(('http://', 'https://')):
        raise HTTPException(status_code=400, detail="URL必须以http://或https://开头")

    # 获取网页内容
    title, content = get_webpage_content(request.url)
    if not content:
        raise HTTPException(status_code=400, detail="无法访问该网页，请检查URL是否正确")

    # 使用AI进行分析
    result = analyze_with_ai(content, title)

    # 构建响应
    response = {
        "is_scam": result["is_scam"],
        "reason": result["reason"],
        "confidence": round(result["confidence"], 2),
        "title": title,
        "risk_level": result["risk_level"],
        "success": True
    }

    print(f"返回检测结果: {response}")
    return response


# 健康检查接口
@app.get("/")
async def root():
    """根路径，返回服务状态"""
    return {
        "status": "服务正常运行",
        "service": "老年AI防诈助手",
        "version": "1.0.0",
        "endpoint": "POST /api/check-url"
    }


@app.get("/health")
async def health_check():
    """健康检查接口"""
    return {"status": "healthy", "timestamp": "2024-01-15T10:00:00Z"}


# 启动服务
if __name__ == "__main__":
    import uvicorn

    print("启动老年AI防诈助手服务...")
    print("服务地址: http://127.0.0.1:8000")
    print("API文档: http://127.0.0.1:8000/docs")

    # 使用这种方式启动，避免警告
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)