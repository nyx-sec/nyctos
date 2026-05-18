import type { SVGProps } from "react";

export interface IconProps {
  className?: string;
  size?: number;
}

type SvgBaseProps = SVGProps<SVGSVGElement> & IconProps;

function svgProps({ className, size = 18 }: IconProps): SvgBaseProps {
  return {
    className,
    width: size,
    height: size,
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.5,
    strokeLinecap: "round",
    strokeLinejoin: "round",
  };
}

export function SetupIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M3 5.5h12" />
      <path d="M3 9h12" />
      <path d="M3 12.5h12" />
      <circle cx="6" cy="5.5" r="1.4" fill="var(--surface)" />
      <circle cx="11" cy="9" r="1.4" fill="var(--surface)" />
      <circle cx="7" cy="12.5" r="1.4" fill="var(--surface)" />
    </svg>
  );
}

export function ReposIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M2.5 4.5c0-.8.6-1.4 1.4-1.4h3.3l1.6 1.8h5.3c.8 0 1.4.6 1.4 1.4v7.2c0 .8-.6 1.4-1.4 1.4H3.9c-.8 0-1.4-.6-1.4-1.4v-9z" />
      <path d="M2.5 7h13" />
    </svg>
  );
}

export function RunsIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M14.5 9A5.5 5.5 0 1 1 9 3.5" />
      <path d="M14.5 4v4h-4" />
      <path d="M9 6v3l2.5 1.5" />
    </svg>
  );
}

export function FindingsIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M9 2.5 2.5 6v4.7c0 3.1 2.8 5.2 6.5 6 3.7-.8 6.5-2.9 6.5-6V6L9 2.5z" />
      <path d="M9 6.3v4" />
      <circle cx="9" cy="12.8" r="0.5" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function ChainsIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M6.5 6.5 4.8 4.8a2.7 2.7 0 0 1 3.8-3.8l1.9 1.9" />
      <path d="m11.5 11.5 1.7 1.7a2.7 2.7 0 0 1-3.8 3.8l-1.9-1.9" />
      <path d="m7 11 4-4" />
    </svg>
  );
}

export function QuarantineIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M4 4.5h10v9c0 .8-.6 1.5-1.5 1.5h-7C4.6 15 4 14.3 4 13.5v-9z" />
      <path d="M3 4.5h12" />
      <path d="M7 2.5h4" />
      <path d="M7.2 8.2 10.8 12" />
      <path d="m10.8 8.2-3.6 3.6" />
    </svg>
  );
}

export function SettingsIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <circle cx="9" cy="9" r="2.2" />
      <path d="M14.2 10.8c.1-.6.1-1.2 0-1.8l1.5-1.1-1.5-2.6-1.8.8c-.5-.4-1-.7-1.6-.9L10.6 3H7.4l-.2 2.2c-.6.2-1.1.5-1.6.9l-1.8-.8-1.5 2.6L3.8 9c-.1.6-.1 1.2 0 1.8l-1.5 1.1 1.5 2.6 1.8-.8c.5.4 1 .7 1.6.9l.2 2.2h3.2l.2-2.2c.6-.2 1.1-.5 1.6-.9l1.8.8 1.5-2.6-1.5-1.1z" />
    </svg>
  );
}
