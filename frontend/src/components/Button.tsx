import { ButtonHTMLAttributes, forwardRef } from "react";

export type ButtonVariant = "default" | "primary" | "ghost" | "danger";
export type ButtonSize = "md" | "sm";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const variantClass: Record<ButtonVariant, string> = {
  default: "",
  primary: "btn--primary",
  ghost: "btn--ghost",
  danger: "btn--danger",
};

const sizeClass: Record<ButtonSize, string> = {
  md: "",
  sm: "btn--sm",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "default", size = "md", className, type = "button", ...rest }, ref) => {
    const classes = ["btn", variantClass[variant], sizeClass[size], className]
      .filter(Boolean)
      .join(" ");
    return <button ref={ref} type={type} className={classes} {...rest} />;
  },
);

Button.displayName = "Button";
