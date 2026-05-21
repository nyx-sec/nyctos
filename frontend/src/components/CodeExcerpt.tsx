import { HTMLAttributes } from "react";

export interface CodeExcerptLine {
  lineno: number;
  code: string;
  highlight?: boolean;
}

export interface CodeExcerptProps extends HTMLAttributes<HTMLDivElement> {
  lines: CodeExcerptLine[];
}

export function CodeExcerpt({ lines, className, ...rest }: CodeExcerptProps) {
  const classes = ["code-excerpt", className].filter(Boolean).join(" ");
  return (
    <div className={classes} {...rest}>
      {lines.map((line) => (
        <div
          key={line.lineno}
          className={
            "code-excerpt__line" + (line.highlight ? " code-excerpt__line--highlight" : "")
          }
        >
          <span className="code-excerpt__lineno">{line.lineno}</span>
          <span className="code-excerpt__code">{line.code}</span>
        </div>
      ))}
    </div>
  );
}
