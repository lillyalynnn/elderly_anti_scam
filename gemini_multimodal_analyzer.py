# gemini_multimodal_analyzer.py
import os
import logging
from typing import Dict, Any, Optional, List
import google.generativeai as genai
import httpx
from urllib.parse import urlparse
import tempfile
import asyncio
from datetime import datetime
import json
import re

logger = logging.getLogger(__name__)


class GeminiMultimodalAnalyzer:
    """
    Google Gemini 2.5 Pro 多模态分析器
    使用最新的Gemini 2.5 Pro模型，提供更强的推理能力和更大的上下文窗口
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        初始化Gemini 2.5 Pro客户端

        Args:
            api_key: Gemini API密钥，默认从环境变量`GEMINI_API_KEY`读取
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API密钥未提供。请设置环境变量 GEMINI_API_KEY")

        # 配置Gemini API
        genai.configure(api_key=self.api_key)

        # 使用 Gemini 2.5 Pro 模型（2025年5月最新版本）
        self.model_name = "gemini-3-flash"

        # 配置生成参数
        generation_config = {
            "temperature": 0.1,  # 低随机性，确保稳定输出
            "top_p": 0.8,
            "top_k": 40,
            "max_output_tokens": 2048,
        }

        # 安全设置
        safety_settings = [
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            }
        ]

        # 初始化模型
        self.model = genai.GenerativeModel(
            model_name=self.model_name,
            generation_config=generation_config,
            safety_settings=safety_settings
        )

        # 异步HTTP客户端
        self.http_client = httpx.AsyncClient(
            timeout=60.0,  # Gemini 2.5 Pro处理大文件可能需要更长时间
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
        )

        logger.info(f"Gemini 2.5 Pro多模态分析器初始化完成，使用模型: {self.model_name}")

    async def analyze_content(self,
                              url: str,
                              analysis_type: str = "detailed",
                              user_context: Optional[str] = None) -> Dict[str, Any]:
        """
        使用Gemini 2.5 Pro分析内容

        Args:
            url: 要分析的内容地址
            analysis_type: 分析模式 ('quick', 'detailed', 'deep')
            user_context: 可选的用户或场景上下文

        Returns:
            包含分析结果的字典
        """
        start_time = datetime.now()

        try:
            logger.info(f"开始Gemini 2.5 Pro多模态分析: {url}, 模式: {analysis_type}")

            # 1. 获取内容
            content_info = await self._fetch_content(url)
            if not content_info:
                logger.warning(f"无法获取内容: {url}")
                return self._create_fallback_result("无法获取或识别该URL的内容。")

            # 2. 构建系统提示词
            system_prompt = self._build_enhanced_system_prompt(analysis_type, user_context)

            # 3. 准备Gemini输入
            gemini_input = [system_prompt]

            if content_info["type"] == "text":
                gemini_input.append(content_info["content"])
                logger.info(f"文本分析，内容长度: {len(content_info['content'])}")
            else:
                # 使用文件上传API
                file_path = content_info["path"]
                file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

                logger.info(f"媒体文件分析: {content_info['mime_type']}, 大小: {file_size / 1024:.2f}KB")

                if file_size > 20 * 1024 * 1024:  # 20MB限制
                    logger.warning(f"文件过大({file_size / 1024 / 1024:.2f}MB)，可能超出Gemini限制")

                try:
                    # 上传文件
                    media_file = genai.upload_file(file_path, mime_type=content_info["mime_type"])
                    gemini_input.append(media_file)

                    # 添加文件描述提示
                    file_desc = f"这是一个{content_info['mime_type']}格式的文件，大小约{file_size / 1024:.1f}KB。"
                    gemini_input.append(file_desc)
                except Exception as e:
                    logger.error(f"文件上传失败: {e}")
                    return self._create_fallback_result(f"文件处理失败: {str(e)[:100]}")

            # 4. 调用Gemini 2.5 Pro API
            logger.info(f"调用Gemini 2.5 Pro API，模型: {self.model_name}")

            try:
                # 使用流式响应，提高大文件处理效率
                response = await self.model.generate_content_async(gemini_input)

                if not response or not response.text:
                    logger.error("Gemini API返回空响应")
                    return self._create_fallback_result("AI分析服务返回空响应")

                # 5. 解析响应
                result = self._parse_enhanced_gemini_response(response.text)

                # 添加性能指标
                processing_time = (datetime.now() - start_time).total_seconds()
                result["processing_time_seconds"] = round(processing_time, 2)
                result["model_used"] = self.model_name

                logger.info(f"Gemini 2.5 Pro分析成功，风险等级: {result.get('risk_level', 'UNKNOWN')}, "
                            f"处理时间: {processing_time:.2f}秒")

                return result

            except Exception as api_error:
                logger.error(f"Gemini API调用失败: {api_error}")
                return self._create_fallback_result(f"AI服务调用失败: {str(api_error)[:100]}")

        except Exception as e:
            logger.error(f"Gemini 2.5 Pro分析过程异常: {e}", exc_info=True)
            return self._create_fallback_result(f"分析服务暂时不可用: {str(e)[:100]}")

        finally:
            # 清理临时文件
            if 'content_info' in locals() and content_info["type"] == "media":
                file_path = content_info.get("path")
                if file_path and os.path.exists(file_path):
                    try:
                        os.unlink(file_path)
                        logger.info(f"清理临时文件: {file_path}")
                    except:
                        pass

    async def _fetch_content(self, url: str) -> Optional[Dict[str, Any]]:
        """
        获取URL内容，支持更大的文件处理
        """
        try:
            # 检查是否是媒体文件
            parsed_url = urlparse(url)
            path_lower = parsed_url.path.lower()

            # 支持的媒体类型
            media_extensions = {
                '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
                '.png': 'image/png', '.gif': 'image/gif',
                '.webp': 'image/webp', '.bmp': 'image/bmp',
                '.mp4': 'video/mp4', '.mov': 'video/quicktime',
                '.avi': 'video/x-msvideo', '.webm': 'video/webm',
                '.mp3': 'audio/mpeg', '.wav': 'audio/wav',
                '.m4a': 'audio/mp4', '.flac': 'audio/flac'
            }

            for ext, mime_type in media_extensions.items():
                if path_lower.endswith(ext):
                    # 下载媒体文件
                    logger.info(f"检测到媒体文件: {ext}, 开始下载...")

                    try:
                        async with self.http_client.stream('GET', url, timeout=120.0) as response:
                            response.raise_for_status()

                            # 检查文件大小
                            content_length = int(response.headers.get('content-length', 0))
                            if content_length > 50 * 1024 * 1024:  # 50MB限制
                                logger.warning(f"文件过大({content_length / 1024 / 1024:.2f}MB)，可能超出处理能力")
                                return None

                            # 保存到临时文件
                            suffix = ext
                            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
                                total_size = 0
                                async for chunk in response.aiter_bytes(chunk_size=8192):
                                    f.write(chunk)
                                    total_size += len(chunk)

                                    # 进度记录
                                    if total_size % (1024 * 1024) == 0:  # 每1MB记录一次
                                        logger.debug(f"已下载: {total_size / 1024 / 1024:.2f}MB")

                                temp_path = f.name

                            logger.info(f"媒体文件下载完成: {temp_path}, 大小: {total_size / 1024:.2f}KB")

                            return {
                                "type": "media",
                                "path": temp_path,
                                "mime_type": mime_type,
                                "source": "direct_media",
                                "size_bytes": total_size
                            }

                    except Exception as download_error:
                        logger.error(f"媒体文件下载失败 {url}: {download_error}")
                        return None

            # 否则作为网页处理
            logger.info(f"按网页处理: {url}")

            try:
                async with self.http_client.get(
                        url,
                        timeout=30.0,
                        headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                            'Accept-Encoding': 'gzip, deflate',
                            'DNT': '1',
                            'Connection': 'keep-alive',
                            'Upgrade-Insecure-Requests': '1'
                        }
                ) as response:
                    response.raise_for_status()

                    content_type = response.headers.get('content-type', '').lower()

                    if 'text/html' in content_type or 'text/plain' in content_type:
                        from bs4 import BeautifulSoup

                        html_content = response.text

                        # 提取网页内容
                        soup = BeautifulSoup(html_content, 'html.parser')

                        # 移除脚本、样式等
                        for element in soup(["script", "style", "nav", "footer", "header", "aside"]):
                            element.decompose()

                        # 获取标题
                        title = soup.title.string if soup.title else "无标题"

                        # 获取正文
                        text = soup.get_text(separator=' ', strip=True)

                        # 智能截断（Gemini 2.5 Pro支持更长上下文，但仍需合理控制）
                        max_length = 30000 if len(text) > 30000 else len(text)
                        truncated_text = text[:max_length]

                        if len(text) > max_length:
                            truncated_text += "...[内容已截断]"

                        logger.info(f"网页内容提取完成，标题: {title}, 长度: {len(truncated_text)}字符")

                        return {
                            "type": "text",
                            "content": f"标题: {title}\n\n内容: {truncated_text}",
                            "title": title,
                            "source": "webpage",
                            "original_length": len(text),
                            "truncated_length": len(truncated_text)
                        }
                    else:
                        logger.warning(f"不支持的内容类型: {content_type}")
                        return None

            except Exception as web_error:
                logger.error(f"网页内容获取失败 {url}: {web_error}")
                return None

        except Exception as e:
            logger.error(f"内容获取过程异常 {url}: {e}")
            return None

    def _build_enhanced_system_prompt(self, analysis_type: str, user_context: Optional[str]) -> str:
        """
        为Gemini 2.5 Pro构建增强的系统提示词
        """
        base_prompt = """你是一位专为老年人设计的"AI防诈骗安全助手"，使用最新的Gemini 2.5 Pro模型进行分析。你的任务是分析用户提供的内容（网页文本、图片、视频、音频等），判断是否存在诈骗风险。

## 核心分析维度：
1. **内容真实性评估** - 检查是否存在虚假信息、夸大宣传、伪造证据
2. **意图分析** - 判断内容是否试图诱导用户进行不安全操作
3. **风险模式识别** - 识别已知的诈骗模式和技术
4. **上下文理解** - 结合内容类型和可能的传播场景

## 重点关注的诈骗类型：
🔴 **高风险类型**：
- 投资理财诈骗：承诺"高收益、零风险、稳赚不赔"
- 冒充公检法：伪造官方文件、制造紧急恐慌
- 虚假中奖/退款：要求支付手续费、保证金
- 情感诈骗：伪装身份建立关系后索要钱财

🟡 **中风险类型**：
- 保健品夸大宣传：承诺治愈疑难杂症
- 金融传销：发展下线、层级返利
- 虚假招聘：要求交押金、培训费
- 网络赌博：诱导参与赌博活动

🟢 **低风险类型**：
- 普通广告宣传
- 正常商业推广
- 无害的娱乐内容

## 特别针对老年人的风险特征：
- 对权威机构（公安、银行、医院）的盲目信任
- 对健康、养老相关信息的过度关注
- 对新技术、新应用的不熟悉
- 对亲情、友情的重视可能被利用

## 输出要求（必须严格遵守）：
你必须输出一个有效的JSON对象，包含以下字段：
{
  "is_scam": boolean,  // 是否是诈骗/高风险内容
  "reason": string,    // 详细、易懂的解释，避免专业术语
  "confidence": float, // 置信度 0.0-1.0
  "risk_level": string, // "HIGH", "MEDIUM", "LOW"
  "detected_keywords": array, // 识别出的风险关键词
  "scam_category": string,    // 诈骗类型分类
  "analysis_insights": array  // 分析洞察点（可选）
}

## 分析模式："""

        if analysis_type == "quick":
            base_prompt += """【快速模式】- 重点扫描最明显的风险信号，30秒内完成分析"""
        elif analysis_type == "deep":
            base_prompt += """【深度模式】- 进行多层次、多角度分析，包括逻辑推理、情感分析、模式匹配"""
        else:  # detailed
            base_prompt += """【详细模式】- 全面分析内容各个方面，提供详尽的判断依据"""

        if user_context:
            base_prompt += f"\n\n## 用户提供的上下文信息：{user_context}"

        base_prompt += "\n\n请开始分析，并确保输出是有效的JSON格式。"

        return base_prompt

    def _parse_enhanced_gemini_response(self, gemini_output: str) -> Dict[str, Any]:
        """
        增强的Gemini响应解析，支持更复杂的JSON结构
        """
        try:
            # 尝试多种JSON提取模式
            json_patterns = [
                r'```json\s*(\{.*?\})\s*```',  # 代码块中的JSON
                r'```\s*(\{.*?\})\s*```',  # 通用代码块
                r'(\{.*?\})',  # 直接JSON
            ]

            json_text = None
            for pattern in json_patterns:
                match = re.search(pattern, gemini_output, re.DOTALL)
                if match:
                    json_text = match.group(1)
                    break

            if not json_text:
                # 如果没有明显JSON标记，尝试提取最像JSON的部分
                lines = gemini_output.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('{') and line.endswith('}'):
                        json_text = line
                        break

            if json_text:
                result = json.loads(json_text)

                # 验证必要字段
                required_fields = ['is_scam', 'reason', 'confidence', 'risk_level']
                if all(field in result for field in required_fields):
                    # 标准化risk_level
                    if 'risk_level' in result:
                        result['risk_level'] = str(result['risk_level']).upper()

                    # 确保detected_keywords是列表
                    if 'detected_keywords' not in result:
                        result['detected_keywords'] = []

                    # 添加原始响应片段用于调试
                    result['raw_snippet'] = gemini_output[:200] + "..." if len(gemini_output) > 200 else gemini_output

                    return result

            # 解析失败，使用降级处理
            logger.warning(f"无法从Gemini响应中解析标准JSON，进行降级处理")
            return self._create_fallback_result("无法解析AI分析结果")

        except json.JSONDecodeError as e:
            logger.error(f"JSON解析失败: {e}")
            return self._create_fallback_result(f"JSON解析错误: {str(e)[:100]}")
        except Exception as e:
            logger.error(f"响应解析异常: {e}")
            return self._create_fallback_result(f"解析异常: {str(e)[:100]}")

    def _create_fallback_result(self, reason: str) -> Dict[str, Any]:
        """创建降级分析结果"""
        return {
            "is_scam": False,
            "reason": f"分析引擎响应异常，已启用安全模式。详情：{reason}",
            "confidence": 0.1,
            "risk_level": "LOW",
            "detected_keywords": ["分析服务降级"],
            "scam_category": "未知",
            "fallback_mode": True
        }

    async def analyze_media_file(self, file_path: str, mime_type: str,
                                 analysis_type: str = "detailed",
                                 user_context: Optional[str] = None) -> Dict[str, Any]:
        """
        分析本地媒体文件
        """
        try:
            if not os.path.exists(file_path):
                return self._create_fallback_result("文件不存在")

            file_size = os.path.getsize(file_path)
            logger.info(f"分析本地文件: {file_path}, 类型: {mime_type}, 大小: {file_size / 1024:.2f}KB")

            # 构建系统提示词
            system_prompt = self._build_enhanced_system_prompt(analysis_type, user_context)

            # 上传文件
            media_file = genai.upload_file(file_path, mime_type=mime_type)

            # 调用Gemini API
            response = await self.model.generate_content_async([system_prompt, media_file])

            if not response or not response.text:
                return self._create_fallback_result("AI分析返回空响应")

            # 解析响应
            result = self._parse_enhanced_gemini_response(response.text)

            # 添加文件信息
            result["file_info"] = {
                "path": file_path,
                "mime_type": mime_type,
                "size_bytes": file_size
            }

            return result

        except Exception as e:
            logger.error(f"媒体文件分析异常: {e}", exc_info=True)
            return self._create_fallback_result(f"文件分析失败: {str(e)[:100]}")

    async def close(self):
        """清理资源"""
        try:
            await self.http_client.aclose()
            logger.info("HTTP客户端已关闭")
        except:
            pass

    async def test_connection(self) -> bool:
        """测试Gemini API连接"""
        try:
            # 简单的连接测试
            test_response = await self.model.generate_content_async("你好")
            return test_response is not None and hasattr(test_response, 'text')
        except Exception as e:
            logger.error(f"Gemini连接测试失败: {e}")
            return False