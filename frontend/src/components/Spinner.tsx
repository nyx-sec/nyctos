export interface SpinnerProps {
  size?: "md" | "lg";
  label?: string;
}

export function Spinner({ size = "md", label = "Loading" }: SpinnerProps) {
  const classes = ["spinner", size === "lg" ? "spinner--lg" : ""].filter(Boolean).join(" ");
  return <span className={classes} role="status" aria-label={label} />;
}
