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

export function EnvironmentsIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M4 3.5h10c.8 0 1.4.6 1.4 1.4v2c0 .8-.6 1.4-1.4 1.4H4c-.8 0-1.4-.6-1.4-1.4v-2c0-.8.6-1.4 1.4-1.4z" />
      <path d="M4 9.7h10c.8 0 1.4.6 1.4 1.4v2c0 .8-.6 1.4-1.4 1.4H4c-.8 0-1.4-.6-1.4-1.4v-2c0-.8.6-1.4 1.4-1.4z" />
      <path d="M5.5 5.9h.1" />
      <path d="M5.5 12.1h.1" />
      <path d="M8 5.9h4.5" />
      <path d="M8 12.1h4.5" />
    </svg>
  );
}

export function OverviewIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M3 8.2 9 3l6 5.2" />
      <path d="M5 7.6v6.1c0 .7.5 1.2 1.2 1.2h5.6c.7 0 1.2-.5 1.2-1.2V7.6" />
      <path d="M7.4 14.9v-4.2h3.2v4.2" />
    </svg>
  );
}

export function RunsIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M14.2 8.6A5.4 5.4 0 1 1 12.6 5L14.2 6.6" />
      <path d="M14.2 3.4v3.2H11" />
      <path d="M9 6.2V9l2.1 1.3" />
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
      <path d="M10.4 2.8H7.6l-.3 2a5.2 5.2 0 0 0-1.3.7l-1.9-.8-1.4 2.4 1.6 1.2a5.2 5.2 0 0 0 0 1.4l-1.6 1.2 1.4 2.4 1.9-.8c.4.3.8.5 1.3.7l.3 2h2.8l.3-2c.5-.2.9-.4 1.3-.7l1.9.8 1.4-2.4-1.6-1.2a5.2 5.2 0 0 0 0-1.4l1.6-1.2-1.4-2.4-1.9.8a5.2 5.2 0 0 0-1.3-.7l-.3-2z" />
    </svg>
  );
}
