# gemini_multimodal_analyzer.py
import os
import logging
from typing import Dict, Any, Optional, List
import google.generativeai as genai
from PIL import Image
import io
import httpx
from urllib.parse import urlparse
import tempfile

logger = logging.getLogger(__name__)


class GeminiMultimodalAnalyzer:
    """
    Google Gemini 1.5 多模态分析器
    支持直接分析图片、视频、音频和文本混合内容。
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        初始化Gemini客户端
        Args:
            api_key: Gemini API密钥，默认从环境变量`GEMINI_API_KEY`读取
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API密钥未提供。请设置环境变量 GEMINI_API_KEY 或在初始化时传入。")

        genai.configure(api_key=self.api_key)
        # 使用 Gemini 1.5 Flash 模型，其在多模态、长上下文和性价比上表现优异
        self.model_name = "models/gemini-1.5-flash"
        self.client = genai.GenerativeModel(self.model_name)
        self.supported_media_types = {'image/jpeg', 'image/png', 'image/webp', 'image/gif',
                                      'video/mp4', 'video/mpeg', 'video/webm',
                                      'audio/mp3', 'audio/wav', 'audio/mpeg'}
        self.http_client = httpx.AsyncClient(timeout=30.0)
        logger.info(f"Gemini多模态分析器初始化完成，使用模型: {self.model_name}")

    async def analyze_content(self,
                              url: str,
                              analysis_type: str = "detailed",
                              user_context: Optional[str] = None) -> Dict[str, Any]:
        """
        核心分析函数：获取URL内容，调用Gemini进行多模态风险分析。

        流程：
        1. 判断URL指向的资源类型（网页、图片、视频、音频）。
        2. 下载内容或获取文本。
        3. 构建适合Gemini的多模态提示词。
        4. 调用Gemini API并解析返回的结构化风险分析结果。

        Args:
            url: 要分析的内容地址
            analysis_type: 分析模式，影响提示词复杂度 ('quick', 'detailed', 'deep')
            user_context: 可选的用户或场景上下文，帮助模型理解

        Returns:
            包含 `is_scam`, `reason`, `confidence`, `risk_level` 等字段的字典。
        """
        try:
            logger.info(f"开始多模态分析: {url}, 模式: {analysis_type}")

            # 1. 判断并获取内容
            content_data = await self._fetch_and_prepare_content(url)
            if not content_data:
                return self._create_fallback_result("无法获取或识别该URL的内容。")

            # 2. 构建Gemini请求内容列表
            contents_for_gemini = []
            mime_type = content_data.get("mime_type", "text/plain")

            if mime_type.startswith("text/"):
                # 网页文本内容
                text = content_data.get("text", "")
                if not text or len(text.strip()) < 10:
                    return self._create_fallback_result("获取的文本内容过少，无法进行有效分析。")
                contents_for_gemini.append(text)
            else:
                # 图片、视频、音频等媒体文件
                file_path = content_data.get("file_path")
                if not file_path or not os.path.exists(file_path):
                    return self._create_fallback_result("媒体文件下载失败。")

                # 使用本地文件路径创建Gemini可识别的文件对象
                media_file = genai.upload_file(file_path, mime_type=mime_type)
                contents_for_gemini.append(media_file)

            # 3. 构建系统提示词 (System Instruction)
            system_prompt = self._build_system_prompt(analysis_type, user_context)

            # 4. 调用Gemini API
            full_contents = [system_prompt] + contents_for_gemini
            logger.info(f"调用Gemini API，内容类型: {mime_type}, 提示词长度: {len(system_prompt)}")

            response = await self.client.generate_content_async(full_contents)

            # 5. 解析Gemini的响应
            result = self._parse_gemini_response(response.text)
            logger.info(f"Gemini分析成功，风险等级: {result.get('risk_level', 'UNKNOWN')}")

            return result

        except Exception as e:
            logger.error(f"Gemini多模态分析过程异常: {e}", exc_info=True)
            return self._create_fallback_result(f"分析服务暂时不可用: {str(e)[:100]}")

    async def _fetch_and_prepare_content(self, url: str) -> Optional[Dict[str, Any]]:
        """
        获取URL内容，并判断其类型。
        返回字典，包含处理后的内容、MIME类型和可能的临时文件路径。
        """
        parsed_url = urlparse(url)
        # 简化示例：假设以常见扩展名结尾的是直接媒体文件
        # 实际应用可更复杂，如通过HEAD请求检查Content-Type
        path_lower = parsed_url.path.lower()
        direct_media_extensions = {'.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
                                   '.png': 'image/png', '.gif': 'image/gif',
                                   '.mp4': 'video/mp4', '.mp3': 'audio/mpeg'}

        for ext, mime in direct_media_extensions.items():
            if path_lower.endswith(ext):
                # 是直接媒体文件，下载到临时文件
                try:
                    # 使用异步客户端下载
                    async with self.http_client.stream('GET', url) as response:
                        response.raise_for_status()
                        # 创建临时文件
                        suffix = ext
                        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp_file:
                            async for chunk in response.aiter_bytes():
                                tmp_file.write(chunk)
                            tmp_path = tmp_file.name
                    logger.info(f"已下载媒体文件到: {tmp_path}, 类型: {mime}")
                    return {"file_path": tmp_path, "mime_type": mime, "source": "direct_media"}
                except Exception as e:
                    logger.error(f"下载媒体文件失败 {url}: {e}")
                    return None

        # 否则，当作网页处理，用原有逻辑抓取文本
        try:
            # 复用原有项目的网页抓取函数，这里需要导入或重新实现简化版
            # 为保持模块独立，此处实现一个简单版本
            async with self.http_client.get(url, headers={'User-Agent': 'Mozilla/5.0'}) as response:
                response.raise_for_status()
                content_type = response.headers.get('content-type', '').lower()
                if 'text/html' in content_type:
                    from bs4 import BeautifulSoup  # 延迟导入
                    soup = BeautifulSoup(response.text, 'html.parser')
                    # 简单清理
                    for script in soup(["script", "style", "nav", "footer", "header"]):
                        script.decompose()
                    text = soup.get_text(separator=' ', strip=True)
                    # 截断到合适长度（Gemini Flash上下文窗口约1M tokens，但文本仍应精简）
                    text = text[:15000]
                    return {"text": text, "mime_type": "text/html", "source": "webpage"}
                else:
                    # 非HTML，可能是不支持的二进制文件
                    logger.warning(f"URL返回非HTML内容: {content_type}")
                    return None
        except Exception as e:
            logger.error(f"获取网页内容失败 {url}: {e}")
            return None

    def _build_system_prompt(self, analysis_type: str, user_context: Optional[str]) -> str:
        """构建引导Gemini进行风险分析的系统提示词。"""
        base_prompt = """你是一位专为老年人设计的“AI防诈骗安全助手”。你的任务是分析用户提供的一段内容（可能是网页文本、图片、视频或音频），判断其是否存在诈骗风险，并以指定的JSON格式输出分析结果。

请重点关注以下诈骗特征：
1.  **财产诈骗**：承诺“高收益、零风险、稳赚不赔”、诱导投资、刷单、冒充客服退款、虚假中奖。
2.  **身份冒充**：冒充“公检法、银行、社保局、疾控中心”等权威机构，制造恐慌，要求转账或提供验证码。
3.  **情感诈骗**：伪装成“美女、帅哥、美国大兵”等身份建立亲密关系，随后以各种理由索要钱财。
4.  **健康误导**：夸大保健品疗效、售卖“伪科学”治疗仪、传播未经证实的恐慌性健康信息。
5.  **信息窃取**：诱导点击不明链接、下载恶意APP、填写银行卡/身份证/密码等个人敏感信息。
6.  **伪造证据**：图片或视频中出现的伪造的“警官证”、“逮捕令”、“法院传票”、“转账记录”、“聊天记录”。

**特别说明**：你分析的内容可能是老年人准备在微信、抖音等平台分享或已经收到的信息。你的分析将帮助阻止他们受骗或传播谣言。

**输出要求**：你必须且只能输出一个JSON对象，包含以下字段：
- `is_scam` (boolean): true 或 false，表示是否是诈骗/高风险内容。
- `reason` (string): 详细、可读的解释，说明判断理由。请用老年人及其子女能理解的语言，**避免使用专业术语**。例如：“该图片展示了一张伪造的‘公安部’逮捕令，含有语法错误，是典型的冒充公检法诈骗手法。”
- `confidence` (float): 你的判断置信度，0.0到1.0之间。
- `risk_level` (string): 风险等级，只能是 `HIGH`、`MEDIUM`、`LOW` 中的一个。
- `detected_keywords` (list of string): 你从内容中识别出的与诈骗相关的关键词或特征描述列表，如[“高收益承诺”, “冒充公安局”, “伪造公章”]。
- `scam_category` (string, 可选): 诈骗类型，如“投资理财诈骗”、“冒充公检法”、“虚假中奖”等。

请确保你的判断基于内容本身，而不是泛泛而谈。如果内容无害，请放心地标记为安全。"""

        # 根据分析模式微调提示词
        if analysis_type == "quick":
            base_prompt += "\n\n**模式**：快速分析。请重点关注最明显、最直接的风险信号。"
        elif analysis_type == "deep":
            base_prompt += "\n\n**模式**：深度分析。请仔细审视内容的每一个细节，包括图片背景、文字语气、逻辑矛盾等，进行多维度推理。"

        if user_context:
            base_prompt += f"\n\n**用户背景信息（供参考）**：{user_context}"

        return base_prompt

    def _parse_gemini_response(self, gemini_output: str) -> Dict[str, Any]:
        """
        解析Gemini的文本输出，提取JSON。
        如果解析失败，则尝试从文本中提取关键信息生成降级结果。
        """
        import json
        import re

        # 尝试直接查找并解析JSON
        try:
            json_match = re.search(r'\{.*\}', gemini_output, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group().strip())
                # 验证必要字段
                required_fields = ['is_scam', 'reason', 'confidence', 'risk_level']
                if all(field in result for field in required_fields):
                    # 确保risk_level是大写字符串
                    if 'risk_level' in result:
                        result['risk_level'] = str(result['risk_level']).upper()
                    return result
        except json.JSONDecodeError:
            pass

        # 解析失败，使用降级处理：从文本中推断
        logger.warning(f"无法从Gemini响应中解析标准JSON，进行降级处理。响应: {gemini_output[:200]}...")
        return self._create_fallback_result(gemini_output)

    def _create_fallback_result(self, reason: str) -> Dict[str, Any]:
        """创建降级/错误情况下的分析结果。"""
        return {
            "is_scam": False,  # 降级时默认为安全，避免误阻断
            "reason": f"分析引擎响应异常，已启用安全模式。详情：{reason}",
            "confidence": 0.1,
            "risk_level": "LOW",
            "detected_keywords": ["分析服务降级"],
            "scam_category": "未知"
        }

    async def close(self):
        """清理资源，如关闭HTTP客户端。"""
        await self.http_client.aclose()