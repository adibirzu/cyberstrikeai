package project

import "strings"

// VisionImageSectionMarker 图片分析 section 标题（与 AppendVisionImageAnalysisIfReady 注入一致）。
const VisionImageSectionMarker = "## Picture analysis"

// VisionImageAnalysisSection 单/多代理共用的图片分析提示（analyze_image；上下文仅保留文字摘要）。
func VisionImageAnalysisSection() string {
	var b strings.Builder
	b.WriteString(VisionImageSectionMarker)
	b.WriteString("\n\n")
	b.WriteString("- For screenshots, CAPTCHA images, login pages or report figures, use analyze_image when available and provide the actual server-side image path.\n")
	b.WriteString("- read_file cannot interpret binary images. An attachment listing such as 📎 image.png: /path supplies the path for analyze_image.\n")
	b.WriteString("- For a saved CAPTCHA image, ask analyze_image to return only the CAPTCHA characters. Refresh and retry if recognition fails; a single screenshot may not solve interactive or behavioral challenges.\n")
	b.WriteString("- Include the image path and requested output format when delegating image/CAPTCHA analysis.\n")
	return b.String()
}

// AppendVisionImageAnalysisIfReady 仅在 vision.enabled 且 model 已配置时追加图片分析提示。
func AppendVisionImageAnalysisIfReady(base string, visionReady bool) string {
	if !visionReady {
		return base
	}
	return AppendSystemPromptBlock(base, VisionImageAnalysisSection())
}
