import React from "react";

export default function BrandMark(props: {
  className?: string;
  title?: string;
}): React.JSX.Element {
  const gradientId = `csxGradient-${props.className || "default"}`;
  return (
    <svg
      className={props.className}
      viewBox="0 0 120 120"
      role="img"
      aria-label={props.title || "CodeSentinelX brand mark"}
    >
      <defs>
        <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#85fff3" />
          <stop offset="55%" stopColor="#34d7ff" />
          <stop offset="100%" stopColor="#0c6da1" />
        </linearGradient>
      </defs>
      <path
        d="M60 8 106 33v54L60 112 14 87V33z"
        fill="none"
        stroke={`url(#${gradientId})`}
        strokeWidth="8"
      />
      <path
        d="M36 50c5-12 13-18 24-18 8 0 16 3 22 10L71 52c-3-4-7-6-12-6-6 0-10 3-13 9-3 7-3 14 0 21 3 6 7 9 13 9 5 0 9-2 12-6l11 10c-6 7-13 10-22 10-11 0-19-6-24-18-5-13-5-27 0-41Z"
        fill={`url(#${gradientId})`}
      />
      <circle cx="88" cy="29" r="5" fill="#85fff3" opacity="0.9" />
      <circle cx="28" cy="87" r="3.5" fill="#34d7ff" opacity="0.65" />
    </svg>
  );
}
