import type { Theme } from "@earendil-works/pi-coding-agent";

// ============================================================================
// Footer status
//
// Pure model + renderer (UI-free, exported for tests). Carries no command, path or
// denyPaths text (ADR-0002). The host joins every extension status onto ONE footer line
// (sorted by key, truncated from the right), so the order below is also the truncation
// priority: gate state, risks, classifier model, counters, info badges.
// ============================================================================

export interface FooterInfo {
	enabled: boolean;
	/** "configured" = an explicit spec resolved; "inherited" = no spec, session model; "unavailable" = spec set but unresolvable, session model used; "none" = no model at all (fail-closed) */
	classifier: { id: string | null; thinking: string; state: "configured" | "inherited" | "unavailable" | "none" };
	/** null = classifierFallbackModel not configured; id null = configured but unresolvable */
	fallback: { id: string | null; mode: "shadow" | "enforce" } | null;
	counts: { allow: number; ask: number; deny: number };
	floorOff: boolean;
	minConfidence: number | null;
	autoDenyOff: boolean;
	subagentGate: "off" | "normal" | "auto";
	/** item 6c (Phase 6): the user's own policy failed to load — shown as a risk badge (ADR-0010). */
	policyDegraded: boolean;
}

type ThemeBg = Parameters<Theme["bg"]>[0];
type FooterTheme = Pick<Theme, "fg" | "bold"> & Partial<Pick<Theme, "bg" | "getBgAnsi">>;

// Nerd Font (nf-fa) code points
const NF_SEP = "\uE0B0"; // powerline right arrow
const NF_SHIELD = "\uF132"; // gate on
const NF_WARN = "\uF071"; // off / risk
const NF_CHIP = "\uF2DB"; // model
const NF_CHECK = "\uF00C"; // allow count
const NF_ASK = "\uF128"; // ask count
const NF_BAN = "\uF05E"; // deny count
const NF_INFO = "\uF05A"; // info block

export function renderFooter(info: FooterInfo, theme: FooterTheme, style: "full" | "compact"): string {
	const { classifier, fallback } = info;
	const modelLabel =
		classifier.state === "none" || classifier.id === null
			? "no model · fail-closed"
			: `${classifier.state === "unavailable" ? "⚠ ↺ " : classifier.state === "inherited" ? "↺ " : ""}${classifier.id}${classifier.thinking !== "off" ? `:${classifier.thinking}` : ""}`;
	const modelColor = classifier.state === "none" ? "error" : classifier.state === "unavailable" ? "warning" : "accent";
	const fallbackText = fallback ? `↳ ${fallback.id === null ? "⚠ unavailable" : fallback.id}·${fallback.mode}` : null;
	const fallbackColor = fallback && fallback.id === null ? "warning" : "muted";
	const infoItems: string[] = [];
	if (info.minConfidence !== null) infoItems.push(`≥${info.minConfidence}%`);
	if (info.autoDenyOff) infoItems.push("autoDeny off");
	if (info.subagentGate === "auto") infoItems.push("subagent auto");
	const risks: { text: string; color: "error" | "warning" }[] = [];
	if (info.floorOff) risks.push({ text: "floor off", color: "error" });
	// "off" is the fail-open deviation now that "normal" is the default (ADR-0006)
	if (info.subagentGate === "off") risks.push({ text: "subagent off", color: "warning" });
	// item 6c (Phase 6): the user's own rules failed to load — model allows are withheld (ADR-0010)
	if (info.policyDegraded) risks.push({ text: "policy degraded", color: "error" });

	const bgFn = theme.bg;
	const bgAnsi = theme.getBgAnsi;
	if (style === "full" && typeof bgFn === "function" && typeof bgAnsi === "function") {
		const bg = (c: ThemeBg, s: string): string => bgFn.call(theme, c, s);
		// The arrow glyph is drawn in the previous block's background color: turn its bg escape into a fg escape
		const bgAsFg = (c: ThemeBg): string | null => {
			const bgEsc = bgAnsi.call(theme, c);
			const fgEsc = bgEsc.replace("\x1b[48;", "\x1b[38;");
			return fgEsc === bgEsc ? null : fgEsc;
		};
		const segs: { bg: ThemeBg; body: string }[] = [];
		if (!info.enabled) {
			segs.push({ bg: "toolPendingBg", body: theme.fg("warning", theme.bold(` ${NF_WARN} AUTO OFF · ungated `)) });
		} else {
			segs.push({ bg: "toolSuccessBg", body: theme.fg("success", theme.bold(` ${NF_SHIELD} AUTO `)) });
			if (risks.length > 0)
				segs.push({ bg: "toolErrorBg", body: ` ${NF_WARN} ${risks.map((r) => theme.fg(r.color, r.text)).join("  ")} ` });
			segs.push({
				bg: "selectedBg",
				body: ` ${NF_CHIP} ${theme.fg(modelColor, modelLabel)}${fallbackText ? ` ${theme.fg(fallbackColor, fallbackText)}` : ""} `,
			});
			segs.push({
				bg: "customMessageBg",
				body: ` ${theme.fg("success", `${NF_CHECK} ${info.counts.allow}`)}  ${theme.fg("warning", `${NF_ASK} ${info.counts.ask}`)}  ${theme.fg("error", `${NF_BAN} ${info.counts.deny}`)} `,
			});
			if (infoItems.length > 0)
				segs.push({ bg: "userMessageBg", body: ` ${NF_INFO} ${infoItems.map((i) => theme.fg("muted", i)).join("  ")} ` });
		}
		let out = "";
		segs.forEach((seg, i) => {
			out += bg(seg.bg, seg.body);
			const next = segs[i + 1];
			const fgEsc = bgAsFg(seg.bg);
			if (next) out += bg(next.bg, fgEsc ? `${fgEsc}${NF_SEP}\x1b[39m` : NF_SEP);
			else out += fgEsc ? `${fgEsc}${NF_SEP}\x1b[39m` : NF_SEP;
		});
		return out;
	}

	// compact (also the full-style fallback on hosts whose theme lacks bg/getBgAnsi)
	if (!info.enabled) return theme.fg("warning", "○ auto off · ungated");
	const parts = [theme.fg("success", "● auto")];
	for (const r of risks) parts.push(theme.fg(r.color, `⚠ ${r.text}`));
	parts.push(`${theme.fg(modelColor, modelLabel)}${fallbackText ? ` ${theme.fg(fallbackColor, fallbackText)}` : ""}`);
	for (const i of infoItems) parts.push(theme.fg("muted", i));
	return parts.join(theme.fg("dim", " · "));
}
