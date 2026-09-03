import { Locale, t } from "../i18n";

export function ScoreGauge({ score, locale }: { score: number; locale: Locale }) {
  const r = 36, cx = 48, cy = 50;
  const startDeg = -210, totalDeg = 240;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const pt = (a: number) => ({ x: cx + r * Math.cos(toRad(a)), y: cy + r * Math.sin(toRad(a)) });
  const arc = (from: number, to: number) => {
    const s = pt(from), e = pt(to), large = to - from > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`;
  };
  const color = score >= 75 ? "#f03c3c" : score >= 50 ? "#f0813c" : score >= 25 ? "#e0c03a" : "#5fd47a";
  const fillDeg = (score / 100) * totalDeg;
  const label = score >= 75 ? t(locale, "scoreCritical") : score >= 50 ? t(locale, "scoreAtRisk") : score >= 25 ? t(locale, "scoreModerate") : t(locale, "scoreSecure");
  return (
    <svg width="90" height="80" viewBox="0 0 96 80">
      <path d={arc(startDeg, startDeg + totalDeg)} fill="none" stroke="rgba(48,90,160,0.14)" strokeWidth="6" strokeLinecap="round"/>
      {score > 0 && <path d={arc(startDeg, startDeg + fillDeg)} fill="none" stroke={color} strokeWidth="6" strokeLinecap="round" style={{filter:`drop-shadow(0 0 4px ${color}80)`}}/>}
      <text x="48" y="52" textAnchor="middle" fontSize="20" fontWeight="800" fontFamily="JetBrains Mono,monospace" fill={color}>{score}</text>
      <text x="48" y="64" textAnchor="middle" fontSize="7" fontWeight="700" fontFamily="Inter,sans-serif" fill="rgba(122,156,192,0.7)" letterSpacing="0.08em">{label}</text>
    </svg>
  );
}

export function ScoreTooltip({ score, locale }: { score: number; locale: Locale }) {
  const rating = score >= 75
    ? (locale === "de" ? "Kritisches Risiko. Sofortige Behebung erforderlich." : "Critical risk. Immediate remediation required.")
    : score >= 50
    ? (locale === "de" ? "Erhebliche Lücken. CRITICAL- und HIGH-Befunde sofort beheben." : "Significant gaps. Address CRITICAL and HIGH findings now.")
    : score >= 25
    ? (locale === "de" ? "Moderates Risiko. HIGH-Befunde innerhalb von 30 Tagen beheben." : "Moderate risk. Address HIGH findings within 30 days.")
    : (locale === "de" ? "Gute Sicherheitslage. Regelmäßige Bewertungen fortsetzen." : "Good posture. Continue regular assessments.");
  return (
    <div className="score-tooltip-wrap">
      <button className="score-info-btn" title={t(locale, "scoreRisk")}>ℹ</button>
      <div className="score-tooltip">
        <strong style={{color:"var(--text)"}}>{t(locale, "scoreRisk")}: {score}/100</strong><br/>
        {t(locale, "scoreExplain1")}<br/>
        {t(locale, "scoreExplain2")}<br/><br/>
        <em style={{color:"var(--c-info)"}}>{rating}</em>
      </div>
    </div>
  );
}
