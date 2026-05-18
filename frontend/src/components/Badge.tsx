import { HTMLAttributes } from "react";

export type BadgeTone = "neutral" | "success" | "warning" | "danger" | "info" | "accent";

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
}

const toneClass: Record<BadgeTone, string> = {
  neutral: "",
  success: "badge--success",
  warning: "badge--warning",
  danger: "badge--danger",
  info: "badge--info",
  accent: "badge--accent",
};

export function Badge({ tone = "neutral", className, ...rest }: BadgeProps) {
  const classes = ["badge", toneClass[tone], className].filter(Boolean).join(" ");
  return <span className={classes} {...rest} />;
}
