package legacytext

// These exact strings are accepted historical input/envelopes only.
var aliases = map[string][]string{
	"Processing...": {PendingAssistant},
	"None":          {"无"}, "None.": {"无。"},
	"Below is the index of the current session bound by the title of the tool": {"以下是当前会话绑定的工具名称索引"},
	"# Skill System": {"# Skill 系统"},
	"Approval":       {"审批"}, "Confirm": {"确认"}, "Audit": {"审核"}, "Owner": {"负责人"}, "Human": {"人工"},
	"Report": {"报告"}, "Summary": {"汇总"}, "Output": {"输出"}, "Notifications": {"通知"}, "Tasks": {"任务"}, "Worksheets": {"工单"},
	"If...": {"如果"}, "Found": {"发现"}, "Existence": {"存在"}, "High": {"高危"}, "New": {"新增"}, "Failed": {"失败"}, "Valid": {"通过"}, "Otherwise...": {"否则"},
	"Sub-domain Name": {"子域名"}, "Port": {"端口"}, "Vulnerabilities": {"漏洞"}, "Hole Scan": {"漏洞扫描"}, "Directory": {"目录"}, "Path": {"路径"}, "Exposure Page": {"暴露页面"}, "Certificate": {"证书"}, "Clouds": {"云"}, "Configuration audit": {"配置审计"}, "Containers": {"容器"}, "Mirror": {"镜像"}, "Information": {"情报"}, "Threatening intelligence": {"威胁情报"},
	"Every day": {"每天"}, "Weekly": {"每周"}, "Timing": {"定时"}, "Cycle": {"周期"}, "Continuous": {"持续"},
	"Authentication code": {"验证码"}, "Graphic Code": {"图形验证码", "图形码"},
	"Structured relationship edges (automatic sync)": {"结构化关系边（自动同步）"},

	"## Attack!":                            {"## 攻击"},
	"## Related":                            {"## 关联"},
	"Assistant text output not captured":    {"未捕获到助手文本输出"},
	"attack chain":                          {"攻击链"},
	"Cancel":                                {"取消"},
	"Character":                             {"字符"},
	"Command execution failed:":             {"命令执行失败:"},
	"Conversation not found":                {"对话不存在"},
	"Destroy points.":                       {"破坏分"},
	"Failed to create dialogue":             {"创建对话失败"},
	"Failed to save upload file":            {"保存上传文件失败"},
	"Failed to save user message":           {"保存用户消息失败"},
	"Found it.":                             {"找到"},
	"Maximum iteration":                     {"达到最大迭代"},
	"Most Annexes":                          {"附件最多"},
	"New Dialogue ":                         {"新对话 "},
	"No Query Found":                        {"未找到与查询 '"},
	"No access.":                            {"无权访问"},
	"No knowledge found matching query '":   {"未找到与查询 '"},
	"Not completed":                         {"仍未完成"},
	"Not found":                             {"未找到"},
	"Original evidence search trail":        {"原始证据检索线索"},
	"Output only":                           {"只输出"},
	"Request":                               {"请求"},
	"Response":                              {"响应"},
	"Task cancelled":                        {"任务已被取消"},
	"Task execution aborted":                {"任务执行中断"},
	"The tool is running in the background": {"工具已提交到后台执行"},
	"This wait has arrived.":                {"本次等待已到达"},
	"This wait reached":                     {"本次等待已到达"},
	"Web page":                              {"网页"},
	"WebShell not found":                    {"未找到该 WebShell"},
	"You are CyberStrikeAI":                 {"你是CyberStrikeAI"},
	"[System Autorun / Auto resume]":        {"【系统自动续跑 / Auto resume】"},
	"does not exist":                        {"不存在"},
	"still incomplete":                      {"仍未完成"},
}

var tokens = map[string]string{
	"是":       "yes",
	"否":       "no",
	"状态":      "status",
	"开启":      "on",
	"开":       "on",
	"关闭":      "off",
	"关":       "off",
	"全部":      "all",
	"仅严重":     "critical",
	"高危以上":    "high",
	"中危以上":    "medium",
	"低危以上":    "low",
	"单代理":     "single",
	"eino单代理": "eino_single",
	"Eino单代理": "eino_single",
}

const (
	ToolGuardPrefix        = "工具调用已被安全规则拦截"
	RuleMarker             = "\n规则: "
	MatchMarker            = "\n匹配内容: "
	FullWidthColon         = "："
	FactDependencyPattern  = `(?im)^[\s\-*]*(?:依赖事实|Dependent facts)\s*[:：]\s*([a-zA-Z0-9][a-zA-Z0-9._/-]*)`
	FactRelatedPattern     = `(?im)^[\s\-*]*(?:相关|Relevant|Related)\s*fact_key\s*[:：]\s*([a-zA-Z0-9][a-zA-Z0-9._/-]*)`
	FactAssociationPattern = `(?im)^##\s*(?:关联|Related)\s*$`
	LedgerSectionPattern   = `(?is)\s*## (?:原始用户输入与约束账本（系统保真）|Original user input and constraints ledger \(system fidelity\))\s*<original_user_intent_ledger>\s*.*?\s*</original_user_intent_ledger>\s*`
)

const HighRiskDraftPattern = `(?i)(隔离|封禁|加固|修复|执行|命令|脚本|删除|清理|阻断|封锁|攻击|利用|getshell|shell|payload|exploit|isolate|ban|harden|repair|remediate|block|execute|command|script|delete|clean|attack)`

const PendingAssistant = "处理中..."

const FactoryAdminDisplayName = "管理员"

var DecisionFieldKeys = []string{"决策", "决定"}
var CommentFieldKeys = []string{"备注", "理由", "说明"}
var auditDecisionTokens = map[string]string{"通过": "approve", "批准": "approve", "允许": "approve", "同意": "approve", "放行": "approve", "拒绝": "reject", "驳回": "reject", "禁止": "reject", "否决": "reject"}

var commandAliases = map[string]string{
	"帮助":   "help",
	"列表":   "list",
	"对话列表": "list",
	"切换":   "switch",
	"继续":   "continue",
	"新对话":  "new",
	"清空":   "clear",
	"状态":   "status",
	"停止":   "stop",
	"角色":   "roles",
	"角色列表": "roles",
	"切换角色": "role",
	"模式":   "mode",
	"模式列表": "modes",
	"切换模式": "mode",
	"删除":   "delete",
	"版本":   "version",
	"项目":   "projects",
	"项目列表": "projects",
	"绑定项目": "bind project",
	"新建项目": "new project",
	"解除项目": "unbind project",
	"绑定":   "bind",
	"解绑":   "unbind",
	"身份":   "whoami",
	"任务":   "task",
	"重命名":  "rename",
	"权限":   "permissions",
	"诊断":   "doctor",
	"确认":   "confirm",
	"取消":   "cancel",
	"漏洞提醒": "vuln alerts",
}
