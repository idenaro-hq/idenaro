import { useState } from "react";

export function InfoTip({ text }: { text: string }) {
  const [show, setShow] = useState(false);
  return (
    <span style={{ position: "relative", display: "inline-flex", alignItems: "center" }}>
      <button
        style={{ background: "none", border: "none", cursor: "pointer", padding: 0, lineHeight: 1, display: "flex", alignItems: "center" }}
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        tabIndex={-1}
        aria-label="Info"
      >
        <svg width="13" height="13" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="8" cy="8" r="7.25" stroke="#6e7681" strokeWidth="1.5"/>
          <rect x="7.25" y="7" width="1.5" height="5" rx="0.75" fill="#6e7681"/>
          <circle cx="8" cy="4.5" r="0.85" fill="#6e7681"/>
        </svg>
      </button>
      {show && (
        <div style={{
          position: "absolute", left: 0, top: "calc(100% + 6px)", zIndex: 100,
          background: "#161b22", border: "1px solid #30363d",
          borderRadius: 6, padding: "8px 10px",
          fontSize: 11, color: "#8b949e", lineHeight: 1.6,
          width: 290, whiteSpace: "pre-wrap", boxShadow: "0 4px 12px rgba(0,0,0,0.4)"
        }}>
          {text}
        </div>
      )}
    </span>
  );
}
